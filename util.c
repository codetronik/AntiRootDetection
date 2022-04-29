#include <linux/mm.h>   
#include <asm/tlbflush.h> // flush_tlb_kernel_range()
#include <linux/ptrace.h> // current_user_stack_pointer()
#include <linux/uaccess.h> // copy_to_user()
#include <linux/ftrace.h> // kallsyms_lookup_name()
#include "util.h"

// callback function
static int change_page_range(pte_t *ptep, pgtable_t token, unsigned long addr,	void *data)
{
    struct page_change_data *cdata = data;
    pte_t pte = READ_ONCE(*ptep);
    pte = clear_pte_bit(pte, cdata->clear_mask);
    pte = set_pte_bit(pte, cdata->set_mask);
    set_pte(ptep, pte);

    return 0;
}

// It was written by referring to /arch/arm64/mm/pageattr.c -> set_memory_rw()
// It is possible outside of VM Area.
void enable_memory_rw(unsigned long addr, int size)
{
    struct mm_struct *init_mm_ptr;
    struct page_change_data data;
	unsigned long start_addr_align = addr & PAGE_MASK;
	unsigned long end_addr_align = PAGE_ALIGN(addr + size);
	
	int page_size = end_addr_align - start_addr_align;

    data.set_mask = __pgprot(PTE_WRITE);
    data.clear_mask = __pgprot(PTE_RDONLY);
	pr_info("[CODETRONIK] rw addr %016lx size %x", start_addr_align, page_size);
    init_mm_ptr = (struct mm_struct *)kallsyms_lookup_name("init_mm");
    if (init_mm_ptr == 0)
    {
        pr_info("[CODETRONIK] init_mm is not found!!", init_mm_ptr);
        return;
    }

    apply_to_page_range(init_mm_ptr, start_addr_align, page_size, change_page_range, &data);
    flush_tlb_kernel_range(start_addr_align, start_addr_align + page_size);
}

char __user *convert_to_user_string(char* str, int len)
{
	char __user *user_pointer = (char __user *)current_user_stack_pointer() - len;
	copy_to_user(user_pointer, str, len);
	return user_pointer;
}
