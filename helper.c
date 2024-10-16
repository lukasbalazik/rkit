#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

#define EI_NIDENT 16
#define SHT_SYMTAB 2  
#define SHT_STRTAB 3  
#define SHN_UNDEF 0
#define SHN_COMMON 0xFFF2

typedef struct {
	uint32_t st_name;  
	uint8_t st_info;  
	uint8_t st_other; 
	uint16_t st_shndx; 
	uint64_t st_value; 
	uint64_t st_size;  
} Elf64_Sym;

typedef struct {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
} Elf64_Ehdr;

typedef struct {
	uint32_t sh_name;	  
	uint32_t sh_type;	  
	uint64_t sh_flags;	 
	uint64_t sh_addr;	  
	uint64_t sh_offset;	
	uint64_t sh_size;	  
	uint32_t sh_link;	  
	uint32_t sh_info;	  
	uint64_t sh_addralign; 
	uint64_t sh_entsize;   
} Elf64_Shdr;

uintptr_t funcAddress; 

void fixA(uintptr_t address, uint32_t ret) {
	unsigned char push_opcode = 0x68;
	unsigned char ret_opcode = 0xC3;

	unsigned char ret_bytes[4];
	ret_bytes[0] = (ret >> 0) & 0xFF;
	ret_bytes[1] = (ret >> 8) & 0xFF;
	ret_bytes[2] = (ret >> 16) & 0xFF;
	ret_bytes[3] = (ret >> 24) & 0xFF;

	int fd;
	off_t offset = (off_t)address;
	unsigned char buffer[6];
	ssize_t bytesRead;

	fd = open("/dev/kmem", O_RDWR);
	if (fd < 0) {
		perror("Error opening /dev/kmem");
		return;
	}

	if (lseek(fd, offset, SEEK_SET) == (off_t)-1) {
		perror("Error seeking /dev/kmem");
		close(fd);
		return;
	}

	bytesRead = read(fd, buffer, sizeof(buffer));
	if (bytesRead < 0) {
		perror("Error reading /dev/kmem");
		close(fd);
		return;
	}

	buffer[0] = push_opcode; 
	buffer[1] = ret_bytes[0]; 
	buffer[2] = ret_bytes[1]; 
	buffer[3] = ret_bytes[2]; 
	buffer[4] = ret_bytes[3]; 
	buffer[5] = ret_opcode; 
 
	if (lseek(fd, offset, SEEK_SET) == (off_t)-1) {
	close(fd);
	return;
	}

	if (write(fd, buffer, 6) != 1) {
	close(fd);
	return;
	}

	close(fd);
}

int validate_elf_header(Elf64_Ehdr *hdr) {
	
	if (memcmp(hdr->e_ident, "\x7F" "ELF", 4) != 0) {
		printf("Invalid ELF magic number\n");
		return -1;
	}
	
	
	if (hdr->e_ident[4] != 2) {  
		fprintf(stderr, "Unsupported ELF class (not 64-bit)\n");
		return -1;
	}

	
	if (hdr->e_ident[5] != 1) {  
		fprintf(stderr, "Unsupported ELF data encoding (not little-endian)\n");
		return -1;
	}

	
	if (hdr->e_ident[6] != 1) {
		fprintf(stderr, "Unsupported ELF version\n");
		return -1;
	}

	return 0;
}


int parse_symbol_table(FILE *file, Elf64_Shdr *section_headers, int num_sections, Elf64_Shdr *string_table, char *search, char *ret) {
	char *strtab = malloc(string_table->sh_size);
	if (!strtab) {
		printf("Failed to allocate memory for string table");
		return -1;
	}
	
	fseek(file, string_table->sh_offset, SEEK_SET);
	fread(strtab, 1, string_table->sh_size, file);

	for (int i = 0; i < num_sections; i++) {
		if (section_headers[i].sh_type == SHT_SYMTAB) {
			
			Elf64_Sym *symtab = malloc(section_headers[i].sh_size);
			if (!symtab) {
				printf("Failed to allocate memory for symbol table");
				free(strtab);
				return -1;
			}

			fseek(file, section_headers[i].sh_offset, SEEK_SET);
			fread(symtab, 1, section_headers[i].sh_size, file);

			int num_symbols = section_headers[i].sh_size / sizeof(Elf64_Sym);
			for (int j = 0; j < num_symbols; j++) {
				if (symtab[j].st_shndx == SHN_UNDEF || symtab[j].st_shndx == SHN_COMMON)
							continue;
				if ((unsigned long)symtab[j].st_value == 0x00)
					continue;
				char *sym_name = strtab + symtab[j].st_name;
				if (!strcmp(sym_name, search)) {
					funcAddress = (unsigned long)symtab[j].st_value;
					uint32_t retAddress = (uint32_t)strtoul(ret, NULL, 0);		
					fixA(funcAddress, retAddress);
				}
		
			}

			free(symtab);
		}
	}

	free(strtab);
	return 0;
}

 int read_elf_header(const char *filename, Elf64_Ehdr *header) {
	FILE *file = fopen(filename, "rb");
	if (!file) {
		printf("Error opening file");
		return -1;
	}

	if (fread(header, 1, sizeof(Elf64_Ehdr), file) != sizeof(Elf64_Ehdr)) {
		printf("Error reading ELF header");
		fclose(file);
		return -1;
	}

	fclose(file);

	return 0;
}


 int read_section_headers(const char *filename, Elf64_Ehdr *elf_header, Elf64_Shdr **section_headers) {
	FILE *file = fopen(filename, "rb");
	if (!file) {
		perror("Error opening file");
		return -1;
	}

	
	*section_headers = malloc(elf_header->e_shentsize * elf_header->e_shnum);
	if (!(*section_headers)) {
		fprintf(stderr, "Failed to allocate memory for section headers\n");
		fclose(file);
		return -1;
	}

	
	fseek(file, elf_header->e_shoff, SEEK_SET);

	if (fread(*section_headers, elf_header->e_shentsize, elf_header->e_shnum, file) != elf_header->e_shnum) {
		perror("Error reading section headers");
		free(*section_headers);
		fclose(file);
		return -1;
	}

	fclose(file);
	return 0;
}



int main(int argc, char *argv[]) {
	Elf64_Ehdr elf_header;

	if (read_elf_header("/boot/kernel/kernel", &elf_header) != 0) {
		printf("Failed to read ELF header\n");
		return 1;
	}

	if (validate_elf_header(&elf_header) != 0) {
		printf("ELF header validation failed\n");
		return 1;
	}
	
	Elf64_Shdr *section_headers = NULL;
	if (read_section_headers("/boot/kernel/kernel", &elf_header, &section_headers) != 0) {
		printf("Failed to read section headers\n");
		return 1;
	}

	int symtab_index = -1;
	int strtab_index = -1;

	for (int i = 0; i < elf_header.e_shnum; i++) {
		if (section_headers[i].sh_type == SHT_SYMTAB) {
		symtab_index = i;
		strtab_index = section_headers[i].sh_link;
		break;
		}
	}

	if (symtab_index == -1 || strtab_index == -1) {
		printf("Symbol table or string table not found\n");
	}

	Elf64_Shdr *string_table = &section_headers[strtab_index];

	FILE *file = fopen("/boot/kernel/kernel", "rb");
	if (!file) {
		printf("Error opening file");
		return 1;
	}

	if (parse_symbol_table(file, section_headers, elf_header.e_shnum, string_table, argv[1], argv[2]) != 0) {
		printf("Failed to parse symbol table\n");
	}

	fclose(file);
	free(section_headers);

	return 0;

}
