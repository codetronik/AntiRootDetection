void enable_memory_rw(unsigned long addr, int size);
char __user *convert_to_user_string(char* str, int len);

struct page_change_data {
    pgprot_t set_mask;
    pgprot_t clear_mask;
};