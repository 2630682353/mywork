#ifndef __HASH_TABLE_H__
#define __HASH_TABLE_H__

#ifdef  __cplusplus
extern "C" {
#endif
	/* element of the hash table's chain list */
typedef struct kv
{
    struct kv* next;
    char* key;
    void* value;
    void(*free_value)(void*);
}kv;

/* HashTable */
typedef struct HashTable
{
    struct kv ** table;
}HashTable;
	extern HashTable* hash_table_new();
	extern void hash_table_delete(HashTable* ht);

	#define hash_table_put(ht,key,value) hash_table_put2(ht,key,value,NULL);
    int hash_table_put2(HashTable* ht, char* key, void* value, void(*free_value)(void*));
    void* hash_table_get(HashTable* ht, char* key);
    void hash_table_rm(HashTable* ht, char* key);

#ifdef  __cplusplus
}
#endif

#endif 