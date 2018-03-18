#ifndef MMAP_AREAS_H
#define MMAP_AREAS_H

int mmap_area_remove(uint64_t addr);
int mmap_area_check(uint64_t addr);
int mmap_areas_init(void);

#endif /* MMAP_AREAS_H */
