#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <stdlib.h>

int main() {
    int prog_fd;
    int map_fd;
    int err;
    int key = 0;
    char buf[7];
    const char *filename = "/usr/local/bin/.honey/systail.o";

    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
   
    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj)){
	fprintf(stderr, "Error opening BPF object file: %s\n", strerror(errno));
	return 1;
    }

    err = bpf_object__load(obj);
    if (err){
	fprintf(stderr, "Error loading BPF object: %s\n", strerror(-err));
        goto cleanup;
	return 1;
    }
    
    prog = bpf_object__find_program_by_name(obj, "inode_create");
    if (!prog) {
	fprintf(stderr, "Error finding the program name.");
	goto cleanup;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "key_to_honey");
    if (map_fd < 0) {
        printf("failed to find map key_to_honey\n");
	return 1;
    }
    
    FILE *f = fopen("/etc/.secret", "r");
    if (!f) {
	printf("unable to open file\n");
	return 1;
    }

    if(!fgets(buf, sizeof(buf), f)) {
	    printf("unable to read file\n");
	    fclose(f);
	    return 1;
    }
    fclose(f);
    
    if(bpf_map_update_elem(map_fd, &key, buf, BPF_ANY) < 0) {
	fprintf(stderr, "failed to update map: %s\n", strerror(-err));
	return 1;
    }
    
    link = bpf_program__attach(prog);
    if (!link) {
	err = -errno;
	fprintf(stderr, "Failed to attach LSM program: %s\n", strerror(-err));
        goto cleanup;
    }

    for (;;) {
        sleep(1);
    }

    return 0;

cleanup:
    bpf_object__close(obj);
    bpf_link__destroy(link);
    return 0;
}
