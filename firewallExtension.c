/*
 *  chardev.c: Creates a read-only char device that says how many times
 *  you've read from the dev file
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <asm/uaccess.h>	/* for put_user */
#include <firewallExtension.h>
#include <stddef.h>
#include <linux/netfilter.h> 
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/compiler.h>
#include <net/tcp.h>
#include <linux/namei.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <linux/proc_fs.h>
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION ("Extensions to the firewall") ;
#define NIPQUAD(addr) \
        ((unsigned char *)&addr)[0], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

#define BUFFERSIZE 80
/* 
 * This function is called whenever a process tries to do an l on our
 * device file. We get two extra parameters (additional to the inode and file
 * structures, which all device functions get): the number of the ioctl called
 * and the parameter given to the ioctl function.
 *
 * If the ioctl is write or read/write (meaning output is returned to the
 * calling process), the ioctl call returns the output of this function.
 */


struct nf_hook_ops *reg;
DEFINE_MUTEX  (devLock);
DEFINE_MUTEX (locker);
static int counter = 0;

typedef struct node{
	struct message* msg;
	struct node* next;
}node; 

typedef struct list{ 
	struct node* head;
	int number;
	size_t clen;
	size_t maxlen;
}list;

typedef struct message{
	char* msg;
	char * port;
	char * path;
	size_t size;
}message;

// the firewall hook - called for each outgoing packet 
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 3, 0)
#error "Kernel version < 4.4 not supported!"
//kernels < 4.4 need another firewallhook!
#endif

struct message* getindex(struct list * l, unsigned int index){
	int i;
	node* currentt;
	currentt = l->head;
	if(l->number-1<index)return -1;
	for(i=0;i<=index;i++){
	if(i!=0){currentt=currentt->next;}

	}
	struct message*  v = currentt->msg;
	return v;
}






unsigned int FirewallExtensionHook (void *priv,
				    struct sk_buff *skb,
				    const struct nf_hook_state *state) {
	mutex_lock(&locker);
    struct tcphdr *tcp;
    struct tcphdr _tcph;
    struct sock *sk;
    struct mm_struct *mm;

  sk = skb->sk;
  if (!sk) {
    printk (KERN_INFO "firewall: netfilter called with empty socket!\n");
	mutex_unlock(&locker);
    return NF_ACCEPT;
  }

  if (sk->sk_protocol != IPPROTO_TCP) {
    printk (KERN_INFO "firewall:netfilter called with non-TCP-packet.\n");
	mutex_unlock(&locker);
    return NF_ACCEPT;
  }

    

    /* get the tcp-header for the packet */
    tcp = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(struct tcphdr), &_tcph);
    if (!tcp) {
	printk (KERN_INFO "Could not get  tcp-header!\n");
	mutex_unlock(&locker);
	return NF_ACCEPT;
    }
    if (tcp->syn) {
	struct iphdr *ip;
	
	printk (KERN_INFO "firewall: Starting connection \n");
	ip = ip_hdr (skb);
	if (!ip) {
	    printk (KERN_INFO "firewall: Cannot get IP header!\n!");
	}
	else {
	    printk (KERN_INFO "firewall: Destination address = %u.%u.%u.%u\n", NIPQUAD(ip->daddr));
	}
	printk (KERN_INFO "firewall: destination port = %d\n", ntohs(tcp->dest)); 
	int i=0;
	int j=0;
	int k=0;
	char curpath[256];		
	char curdir[256];
		    char cmdlineFile[BUFFERSIZE];
		    int res;
	for(i=0;i<l->number;i++){
		char portstring[10];
		sprintf(portstring, "%d",ntohs(tcp->dest));
		if(strcmp(portstring,getindex(l,i)->port)==0){
			j++;
			k++;
			printk (KERN_INFO "PORT INTERDIT \n"); 
			struct path path;
			pid_t mod_pid;
			struct dentry *procDentry;
			struct dentry *parent;
			struct dentry *paparent;
			struct dentry *currentdentry;
			mod_pid = current->pid;
			snprintf (cmdlineFile, BUFFERSIZE, "/proc/%d/exe", mod_pid);
			printk (KERN_INFO " IT S  %s!\n", cmdlineFile); 
			res = kern_path (cmdlineFile, LOOKUP_FOLLOW, &path);
		    if (res) {
			  tcp_done (sk); /* terminate connection immediately */			 
			printk (KERN_INFO "Could not get dentry for %s !\n", cmdlineFile);
			mutex_unlock(&locker);
			return NF_DROP;
		    }

			procDentry = path.dentry;
			currentdentry = path.dentry;
			strcpy(curpath,"");
			while(strcmp(currentdentry->d_name.name,"/")!=0){
				sprintf(curdir,"%s\0", currentdentry->d_name.name);

				strcat(curdir,curpath);
				sprintf(curpath,"/%s\0", curdir);
				currentdentry=currentdentry->d_parent;
			}

			strcat(curpath,"\n");
			printk (KERN_INFO "curpath: %s\n", curpath);
			char * returnedpath= getindex(l,i)->path;
			printk (KERN_INFO "returnedpath: %s\n", returnedpath);
			if(strcmp(curpath,getindex(l,i)->path)==0){
				
					    printk (KERN_INFO "PACKET ACCEPTED\n");
							mutex_unlock(&locker);
					    return NF_ACCEPT;
			}
			parent = procDentry->d_parent;
			paparent = parent->d_parent;
			printk (KERN_INFO "The name iiis %s\n", procDentry->d_name.name);

			printk (KERN_INFO "The name of the parent is %s\n", parent->d_name.name);
			printk (KERN_INFO "The name of the parent is %s\n", parent->d_name.name);
			char mybuf[256];


			printk (KERN_INFO "The name of the parent is %s\n", paparent->d_name.name);
			printk (KERN_INFO "The name of the parent is %s\n", paparent->d_parent->d_name.name);    
			printk (KERN_INFO "The name of the parent is %s\n", paparent->d_parent->d_parent->d_name.name);
			path_put(&path);
		}
		else{
		}

	

	}
	if(j==0){

		printk (KERN_INFO "PORT AUTORISÉ \n"); 	
	mutex_unlock(&locker);
		return NF_ACCEPT;	
		}
		else{
			  tcp_done (sk); /* terminate connection immediately */
	    printk (KERN_INFO "Conection shut down\n");
	mutex_unlock(&locker);
	    return NF_DROP;		
		}
	 
	if (in_irq() || in_softirq() || !(mm = get_task_mm(current))) {
		printk (KERN_INFO "Not in user context - retry packet\n");
	mutex_unlock(&locker);
		return NF_ACCEPT;
	}
	mmput(mm);

	if (ntohs (tcp->dest) == 80) {
	    tcp_done (sk); /* terminate connection immediately */
	    printk (KERN_INFO "Conection shut down\n");
	mutex_unlock(&locker);
	    return NF_DROP;
	}
    }
	mutex_unlock(&locker);
    return NF_ACCEPT;	
}

static struct nf_hook_ops firewallExtension_ops = {
	.hook    = FirewallExtensionHook,
	.pf      = PF_INET,
	.priority = NF_IP_PRI_FIRST,
	.hooknum = NF_INET_LOCAL_OUT
};





void initlist(struct list * l){
	l->head=(struct node*)kmalloc(sizeof(struct node),GFP_KERNEL);
	l->head->next=NULL;
	l->clen=0;
	l->maxlen=2097152;
	max_list_size=2097152;
	printk(KERN_INFO "list initialized\n");
	l->number=0;
}

void rule(struct  message* message){
	char *prt;
	char *ex;
	char * m = message->msg;
	prt = strsep(&m," ");
    	printk (KERN_INFO "port: %s\n", prt);
	message->port=prt;
	ex = strsep(&m," ");
    	printk (KERN_INFO "ex: %s\n", ex);
	message->path=ex;
}

int append(list * l, struct message* data){	
	mutex_lock(&locker);
	if(l->clen+(data->size)>l->maxlen) return 2;
	struct node* new, *currentt;

	 new=(struct node*)kmalloc(sizeof(node),GFP_KERNEL);
	if(new==NULL)return -1;
	mutex_lock(&devLock);
	if(l->number==0){

		if(l->head==NULL){
			kfree(l->head);

			l->head=new;
			l->head->next=NULL;
			l->clen=0;
			l->maxlen=max_list_size;
			printk(KERN_INFO "list initialized again\n");
			l->number=0;
		}
		l->head->msg=data;
		l->number=l->number+1;
		l->clen=l->clen+data->size;
	printk(KERN_INFO "list added initialized with this message: %s\n",data->msg);

	mutex_unlock(&devLock);
	mutex_unlock(&locker);
		return 0;
	}
	else{

	

	new->msg=data;
	new->next=NULL;

	currentt= l->head;
		while(currentt->next!=NULL){
		currentt=currentt->next;
		}	

	currentt->next=new;
	l->number=l->number+1;
	l->clen=l->clen+data->size;

	printk(KERN_INFO "list added with this message: %s\n",data->msg);
	mutex_unlock(&devLock);
	mutex_unlock(&locker);
	return 0;
	}
}

struct message*  get(list * l){
	mutex_lock(&devLock);
	if(l->number==0){ mutex_unlock(&devLock); return NULL;}
	int i;

	node* currentt;
	currentt = l->head;

	l->clen=l->clen-currentt->msg->size;

	struct message* c= currentt->msg;
	l->head=currentt->next;
	l->number=l->number-1;
		
		kfree(currentt);
	mutex_unlock(&devLock);
	return c;
}


/*
 * This function is called when the module is loaded
 */
int init_module(void)
{

int errno;


  if (errno) {
    printk (KERN_INFO "Firewall extension could not be registered !\n");
  } 
  else {
    printk(KERN_INFO "Firewall extensions module loaded\n");
  }

        Major = register_chrdev(0, DEVICE_NAME, &fops);

	if (Major < 0) {

	  return Major;
	}

	l=(struct list*)kmalloc(sizeof(struct list),GFP_KERNEL);
        initlist(l);
  errno = nf_register_hook (&firewallExtension_ops); /* register the hook */

	printk(KERN_INFO "'mknod /dev/%s c %d 0'.\n", DEVICE_NAME, Major);



  // A non 0 return means init_module failed; module can't be loaded.
  return errno;
}

/*
 * This function is called when the module is unloaded
 */
void cleanup_module(void)
{
	/*  Unregister the device */
	struct node* currentt;
	currentt = l->head;	
	struct node* following;
	while(currentt!=NULL){
		following =(struct node*) currentt->next;
		kfree(currentt->msg->msg);
		kfree(currentt->msg);
		kfree(currentt);
		currentt=following;
	}
	l = NULL;
	printk(KERN_INFO "unloaded");
	unregister_chrdev(Major, DEVICE_NAME);
    nf_unregister_hook (&firewallExtension_ops); /* restore everything to normal */
    printk(KERN_INFO "Firewall extensions module unloaded\n");
	return SUCCESS;


	
}

static long device_ioctl(struct file *file,	/* see include/linux/fs.h */
		 unsigned int ioctl_num,	/* number and param for ioctl */
		 unsigned long ioctl_param)
{

}
/*
 * Methods
 */

/* 
 * Called when a process tries to open the device file, like
 * "cat /dev/mycharfile"
 */
static int device_open(struct inode *inode, struct file *file)
{
			
 mutex_lock (&devLock);
if (Device_Open) {
mutex_unlock (&devLock);
return -EAGAIN;
}
Device_Open++;
mutex_unlock (&devLock);
 counter++;
//sprintf(msg, "I already told you %d times Hello world!\n", counter++);
msg_Ptr = msg;

try_module_get(THIS_MODULE);
return SUCCESS;
}


/* Called when a process closes the device file. */
static int device_release(struct inode *inode, struct file *file)
{

mutex_lock (&devLock);
Device_Open--;         /* We're now ready for our next caller */
mutex_unlock (&devLock);
/*
 * Decrement the usage count, or else once you opened the file, 
you'll
 * never get get rid of the module.
 */
module_put(THIS_MODULE);
return 0;
}

/* 
 * Called when a process, which already opened the dev file, attempts to
 * read from it.
 */
static ssize_t device_read(struct file *filp,	/* see include/linux/fs.h   */
			   char *buffer,	/* buffer to fill with data */
			   size_t length,	/* length of the buffer     */
			   loff_t * offset)
{
	/*
	 * Number of bytes actually written to the buffer 
	 */
	int bytes_read = 0;

	/* result of function calls */

	int result;
	//struct message * m=get(l);
	//if(m!=NULL){printk(KERN_ALERT " read list.\n the message is: %s",m->msg);copy_to_user(buffer,m->msg,m->size); return buffer;};
	//if(m==NULL){	printk(KERN_ALERT "null.\n the message is: %s",m);return -EAGAIN;} 	

	/*
	 * If we're at the end of the message, 
	 * return 0 signifying end of file 
	 */
	if (*msg_Ptr == 0)
		return 0;

	/* 
	 * Actually put the data into the buffer 
	 */
	while (length && *msg_Ptr) {

		/* 
		 * The buffer is in the user data segment, not the kernel 
		 * segment so "*" assignment won't work.  We have to use 
		 * put_user which copies data from the kernel data segment to
		 * the user data segment. 
		 */
		result = put_user(*(msg_Ptr++), buffer++);
		if (result != 0) {
		         return -EFAULT;
		}
		    
		length--;
		bytes_read++;
	}

	/* 
	 * Most read functions return the number of bytes put into the buffer
	 */
	return bytes_read;
}

/* Called when a process writes to dev file: echo "hi" > /dev/hello  */
static ssize_t
device_write(struct file *filp, const char *buff, size_t len, loff_t * off)
{	if(len>4096){return -EINVAL;};
	struct message* my_mess ;
	my_mess= (struct message*)kmalloc(sizeof(struct message), GFP_KERNEL);
	char * my_buff = (char*)kmalloc(len+1,GFP_KERNEL);
	if(copy_from_user(my_buff,buff,len)!=0){
		printk(KERN_INFO "Copy_from_user failed");
		return -EAGAIN;
	};
	my_buff[len]='\0'; 
	my_mess->msg=my_buff;
	my_mess->size=len;
	int res;

	if(strcmp(my_mess->msg,"L\n")==0){
		int i=0;		
		for(i=0;i<l->number;i++){
			printk(KERN_INFO "FIrewall setup: %s %s", getindex(l,i)->port , getindex(l,i)->path);
		}
	
	}else{
		rule(my_mess);
		res=append(l,my_mess);
	}


	if(res==2) return -EAGAIN;
	return len;

}
