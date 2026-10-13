/*
 * SPDX-FileCopyrightText: 2023-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

#include "private/elf_types.h"
#include "private/elf_symbol.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct elf_file {
    uint8_t *payload;
    size_t size;
} elf_file_t;

/**
 * @brief Symbol table type
 *
 * A symbol table is an array of esp_elfsym structures terminated with ESP_ELFSYM_END.
 */
typedef const struct esp_elfsym esp_elf_symbol_table_t;

/**
 * @brief Randomly-accessible ELF byte source.
 *
 * The loader only needs to read the ELF image by offset, so callers can back an
 * image with anything (a memory buffer, a file on a filesystem, a network
 * stream). This lets relocate() avoid holding the whole image in RAM.
 *
 * All offsets and sizes are relative to the start of the ELF image.
 */
typedef struct elf_source {
    /**
     * @brief Total size of the image in bytes, or (size_t)-1 if unknown.
     */
    size_t (*size)(void *ctx);

    /**
     * @brief Read @p len bytes at @p offset into @p buf.
     *
     * @return 0 on success, or a negative errno on failure.
     */
    int (*read)(void *ctx, size_t offset, void *buf, size_t len);

    /**
     * @brief Release resources owned by the source. Optional, may be NULL.
     */
    void (*close)(void *ctx);

    void *ctx;                          /*!< Opaque context passed to the callbacks */
} elf_source_t;

/**
 * @brief Open and load an ELF file into memory.
 *
 * @param file - Pointer to elf_file_t structure to store loaded file content
 * @param name - Filename (without path) of the ELF file to open
 *
 * @return 0 on success, -1 on failure with errno set. Error cases include:
 *         - Invalid parameters
 *         - Path generation failure
 *         - File open/read errors
 *         - Memory allocation failures
 *
 * @note The actual file path will be constructed as "FS_PATH/name"
 * @note Allocates memory for file content using esp_elf_malloc()
 */
int esp_elf_open(elf_file_t *file, const char *name);

/**
 * @brief Close ELF file and release associated resources.
 *
 * @param file - Pointer to opened elf_file_t structure
 *
 * @note Releases memory allocated by esp_elf_open() for payload data
 * @note Should be called paired with esp_elf_open() to prevent memory leaks
 * @note If file is NULL, this function does nothing (null-safe)
 */
void esp_elf_close(elf_file_t *file);

/**
 * @brief Map symbol's address of ELF to physic space.
 *
 * @param elf - ELF object pointer
 * @param sym - ELF symbol address
 *
 * @return Mapped physic address.
 */
uintptr_t esp_elf_map_sym(esp_elf_t *elf, uintptr_t sym);

/**
 * @brief Initialize ELF object.
 *
 * @param elf - ELF object pointer
 *
 * @return ESP_OK if success or other if failed.
 */
int esp_elf_init(esp_elf_t *elf);

/**
 * @brief Decode and relocate ELF data.
 *
 * @param elf - ELF object pointer
 * @param pbuf - ELF data buffer
 *
 * @return ESP_OK if success or other if failed.
 *
 * @note The whole image must be resident in @p pbuf.
 */
int esp_elf_relocate(esp_elf_t *elf, const uint8_t *pbuf);

/**
 * @brief Decode and relocate ELF data read from an ELF source.
 *
 * Identical to esp_elf_relocate() except the image is read on demand through
 * @p src, so the full image does not need to be resident. Only the ELF headers,
 * the section/relocation tables and the loaded sections are ever held in RAM.
 *
 * @param elf - ELF object pointer
 * @param src - ELF byte source
 *
 * @return ESP_OK if success or other if failed.
 */
int esp_elf_relocate_source(esp_elf_t *elf, const elf_source_t *src);

/**
 * @brief Request running relocated ELF function.
 *
 * @param elf  - ELF object pointer
 * @param opt  - Request options
 * @param argc - Arguments number
 * @param argv - Arguments value array
 *
 * @return ESP_OK if success or other if failed.
 */
int esp_elf_request(esp_elf_t *elf, int opt, int argc, char *argv[]);

/**
 * @brief Deinitialize ELF object.
 *
 * @param elf - ELF object pointer
 *
 * @return None
 */
void esp_elf_deinit(esp_elf_t *elf);

/**
 * @brief Print header description information of ELF.
 *
 * @param pbuf - ELF data buffer
 *
 * @return None
 */
void esp_elf_print_ehdr(const uint8_t *pbuf);

/**
 * @brief Print program header description information of ELF.
 *
 * @param pbuf - ELF data buffer
 *
 * @return None
 */
void esp_elf_print_phdr(const uint8_t *pbuf);

/**
 * @brief Print section header description information of ELF.
 *
 * @param pbuf - ELF data buffer
 *
 * @return None
 */
void esp_elf_print_shdr(const uint8_t *pbuf);

/**
 * @brief Print section information of ELF.
 *
 * @param pbuf - ELF data buffer
 *
 * @return None
 */
void esp_elf_print_sec(esp_elf_t *elf);

/**
 * @brief Register symbol table to global symbol tables array.
 *
 * @param symbol_table - Pointer to symbol table structure (array of esp_elfsym terminated by ESP_ELFSYM_END)
 *
 * @return 0 if success, -EINVAL if symbol_table is NULL, -EEXIST if already registered, -ENOMEM if no space.
 *
 * @note This function is not thread-safe. External synchronization must be used if calling
 *       this function concurrently from multiple threads.
 */
int esp_elf_register_symbol(esp_elf_symbol_table_t *symbol_table);

/**
 * @brief Unregister symbol table from global symbol tables array.
 *
 * @param symbol_table - Pointer to symbol table structure to remove
 *
 * @return 0 if success, -EINVAL if symbol_table is NULL or symbol table not found.
 *
 * @note This function is not thread-safe. External synchronization must be used if calling
 *       this function concurrently from multiple threads.
 */
int esp_elf_unregister_symbol(esp_elf_symbol_table_t *symbol_table);

/**
 * @brief Find symbol address by symbol name in registered tables.
 *
 * @param sym_name - Symbol name string to search
 *
 * @return Symbol address if found, 0 if not found.
 * @note Search order is reverse registration order (latest registered first).
 */
uintptr_t esp_elf_find_symbol(const char *sym_name);

#ifdef __cplusplus
}
#endif
