#!/usr/bin/env python3 -I
# Add UMHDBG printks to the lab kernel to find where do_execve fails with
# kernel-pointer argv/envp (the -EFAULT). Idempotent: skips if markers exist.
# Usage: patch-umh-debug.py <kernel-src-root>
import sys, pathlib

root = pathlib.Path(sys.argv[1])

def patch(rel, old, new):
    p = root / rel
    s = p.read_text()
    if new in s:
        return 'already'
    assert old in s, f'pattern not found in {rel}'
    p.write_text(s.replace(old, new, 1))
    return 'patched'

# 1. fs/namei.c: getname() path copy failure
print(patch('fs/namei.c',
"""	len = strncpy_from_user(kname, filename, max);
	if (unlikely(len < 0)) {
		err = ERR_PTR(len);
		goto error;
	}""",
"""	len = strncpy_from_user(kname, filename, max);
	if (unlikely(len < 0)) {
		printk(KERN_WARNING "UMHDBG: getname ret=%d\\n", len);
		err = ERR_PTR(len);
		goto error;
	}"""))

# 2. fs/exec.c: count() argv/envp array read failure
print(patch('fs/exec.c',
"""			if (IS_ERR(p))
				return -EFAULT;""",
"""			if (IS_ERR(p)) {
				printk(KERN_WARNING "UMHDBG: count EFAULT at i=%d\\n", i);
				return -EFAULT;
			}"""))

# 3. fs/exec.c: copy_strings() string copy failure
print(patch('fs/exec.c',
"""out:
	if (kmapped_page) {
		flush_kernel_dcache_page(kmapped_page);
		kunmap(kmapped_page);
		put_arg_page(kmapped_page);
	}
	return ret;
}

/*
 * Like copy_strings, but get argv and its values from kernel memory.
 */""",
"""out:
	if (ret)
		printk(KERN_WARNING "UMHDBG: copy_strings ret=%d argcleft=%d\\n", ret, argc);
	if (kmapped_page) {
		flush_kernel_dcache_page(kmapped_page);
		kunmap(kmapped_page);
		put_arg_page(kmapped_page);
	}
	return ret;
}

/*
 * Like copy_strings, but get argv and its values from kernel memory.
 */"""))

# 4. kernel/kmod.c: UMH child addr_limit + exec retval
print(patch('kernel/kmod.c',
"""	retval = do_execve(sub_info->path,
			   (const char __user *const __user *)sub_info->argv,
			   (const char __user *const __user *)sub_info->envp);""",
"""	printk(KERN_WARNING "UMHDBG: child al=%08lx path=%s argv=%p\\n",
	       current_thread_info()->addr_limit, sub_info->path,
	       sub_info->argv);
	retval = do_execve(sub_info->path,
			   (const char __user *const __user *)sub_info->argv,
			   (const char __user *const __user *)sub_info->envp);
	if (retval)
		printk(KERN_WARNING "UMHDBG: exec ret=%d\\n", retval);"""))

# 5. drivers/usb/serial/usb-serial.c: probe caller (khubd) addr_limit
print(patch('drivers/usb/serial/usb-serial.c',
"""{
	struct device *ddev = &interface->dev;""",
"""{
	printk(KERN_WARNING "UMHDBG: probe al=%08lx\\n",
	       current_thread_info()->addr_limit);
	struct device *ddev = &interface->dev;"""))

# 6. kernel/kmod.c: what call_usermodehelper actually received in its args
print(patch('kernel/kmod.c',
"""int call_usermodehelper(char *path, char **argv, char **envp, int wait)
{
	struct subprocess_info *info;""",
"""int call_usermodehelper(char *path, char **argv, char **envp, int wait)
{
	printk(KERN_WARNING "UMHDBG: umh entry path=%s argv=%p envp=%p wait=%d\\n",
	       path, argv, envp, wait);
	struct subprocess_info *info;"""))

# 7. drivers/usb/core/config.c: what each endpoint parse consumed/assigned
print(patch('drivers/usb/core/config.c',
"""	endpoint->extra = buffer;
	i = find_next_descriptor(buffer, size, USB_DT_ENDPOINT,
			USB_DT_INTERFACE, &n);
	endpoint->extralen = i;""",
"""	endpoint->extra = buffer;
	i = find_next_descriptor(buffer, size, USB_DT_ENDPOINT,
			USB_DT_INTERFACE, &n);
	endpoint->extralen = i;
	printk(KERN_WARNING "EPDBG: parse blen=%d addr=%02x buf=%p extra=%p xlen=%d\\n",
	       d->bLength, d->bEndpointAddress, buffer, endpoint->extra, i);"""))

# 8. drivers/usb/serial/usb-serial.c: what the probe loop actually sees
print(patch('drivers/usb/serial/usb-serial.c',
"""	for (i = 0; i < iface_desc->desc.bNumEndpoints; ++i) {
		endpoint = &iface_desc->endpoint[i].desc;

		if (usb_endpoint_is_bulk_in(endpoint)) {""",
"""	for (i = 0; i < iface_desc->desc.bNumEndpoints; ++i) {
		endpoint = &iface_desc->endpoint[i].desc;
		printk(KERN_WARNING "EPDBG: probe i=%d ep=%p blen=%d addr=%02x extra=%p xlen=%d\\n",
		       i, &iface_desc->endpoint[i], endpoint->bLength,
		       endpoint->bEndpointAddress, iface_desc->endpoint[i].extra,
		       iface_desc->endpoint[i].extralen);

		if (usb_endpoint_is_bulk_in(endpoint)) {"""))
