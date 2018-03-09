#include "plugin.h"

static void *handle = NULL;
const char *DEFAULT_FNTABLE_SYMBOL_NAME = "plugin_fntable";

struct fntable *plugin_load_default(const char *filename) {
    return plugin_load(filename, DEFAULT_FNTABLE_SYMBOL_NAME);
}

struct fntable *plugin_load(const char *filename, const char *fntable_symbol_name) {
    if(handle != NULL) {
        printlnd("handle is already active, close first");
        return NULL;
    }
    
    handle = dlopen(filename, RTLD_LAZY);
    if(handle == NULL) {
        return NULL;
    }
    return dlsym(handle, fntable_symbol_name);
}

void plugin_unload(void) {
    int retval = 0;
    if(handle != NULL) {
        retval = dlclose(handle);
    }
    if(retval == 0) {
        handle = NULL;
    }
}