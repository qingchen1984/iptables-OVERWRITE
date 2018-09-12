/* Shared library add-on to iptables for the OVERWRITE target
 * (C) 2018 by Nick Huber <nhuber@securityinnovation.com>
 *
 * This program is distributed under the terms of GNU GPL
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <linux/netfilter/xt_string.h>
#include <xtables.h>
#include <linux/netfilter_ipv4/ipt_OVERWRITE.h>

enum {
	O_OFFSET = 0,
	O_OVERWRITE_STR,
	O_OVERWRITE_HEX,
	O_OFFLOAD,	
	F_OVERWRITE_STR = 1 << O_OVERWRITE_STR,
	F_OVERWRITE_HEX = 1 << O_OVERWRITE_HEX,
	F_OFFLOAD = 1 << O_OFFLOAD,
	F_ANY     = F_OVERWRITE_STR | F_OVERWRITE_HEX | F_OFFLOAD,
};

#define s struct ipt_OVERWRITE_info
static const struct xt_option_entry OVERWRITE_opts[] = {
	//manages how the xtables parse handles arguments
	//see xtables.h for documentation
	{.name = "offset", .type = XTTYPE_UINT16, .id = O_OFFSET,
		.flags = XTOPT_MAND | XTOPT_PUT, XTOPT_POINTER(s, offset)},
	{.name = "overwrite-str", .type = XTTYPE_STRING, .id = O_OVERWRITE_STR,
		.excl = F_OVERWRITE_HEX},
	{.name = "overwrite-hex", .type = XTTYPE_STRING, .id = O_OVERWRITE_HEX,
		.excl = F_OVERWRITE_STR},
	{.name = "offload", .type = XTTYPE_NONE, .id = O_OFFLOAD}, 
	XTOPT_TABLEEND,
};
#undef s

//Prints help prompt
static void OVERWRITE_help(void)
{
	printf( "OVERWRITE target options\n"
			"  --overwrite-str <string>		overwrite section of packet with string \n"
			"  --overwrite-hex <hex string>		overwrite section by repeating string\n"
			"  --offset <value 0-65535> 		offset from beginning of ip packet to start writing\n"
			"  --offload				offloads checksum processing of some checksums to NIC\n"
			"					by default the extension processes all checksums internally\n"
			" Always recalculates layer3 checksum. Depending on protocol, recalculates layer4+ checksum\n");
}

//Parses string if the pattern was passed in via --overwrite-str
static void parse_string(const char *s, struct ipt_OVERWRITE_info *info)
{
	/* xt_string does not need \0 at the end of the pattern */
	if (strlen(s) <= XT_STRING_MAX_PATTERN_SIZE) {
		strncpy(info->pattern, s, XT_STRING_MAX_PATTERN_SIZE);
		info->patlen = strnlen(s, XT_STRING_MAX_PATTERN_SIZE);
		return;
	}
	xtables_error(PARAMETER_PROBLEM, "STRING too long, max size: 128");
}

//Parses string if the patter was passed in via --overwrite-hex
static void parse_hex_string(const char *s, struct ipt_OVERWRITE_info *info)
{
	int i, slen, sindex=0;
	char hextmp[3];
	hextmp[2] = '\0';
	slen = strlen(s);

	/* sanity checks for valid hex string */
	if (slen < 2) {
		xtables_error(PARAMETER_PROBLEM, "STRING must contain at least two chars");
	}
	if (slen > XT_STRING_MAX_PATTERN_SIZE * 2){
		xtables_error(PARAMETER_PROBLEM, "STRING too long, max size: 128 (256 hex digits)");
	}
	if (slen % 2 == 1) {
		xtables_error(PARAMETER_PROBLEM, "STRING must have an even length");
	}
	for (i = 0; s[i]; i++){
		if ( !isxdigit(s[i])){
			xtables_error(PARAMETER_PROBLEM, "STRING must contain only hexadecimal characters");
		}
	}

	for (i = 0; s[i]; i+=2){
		hextmp[0] = s[i];
		hextmp[1] = s[i+1];
		info->pattern[sindex] = (char) strtol(hextmp, NULL, 16);
		sindex++;
	}
	info->patlen = sindex;
}

//Called for each option that the parser thinks is part of the module
//manages which string parser is used and sets whether or not to offload the checksum
static void OVERWRITE_parse(struct xt_option_call *cb)
{
	struct ipt_OVERWRITE_info *info = cb->data;
	if (info->offload != IPT_CSUM_OFFLOAD && info->offload != IPT_CSUM_NO_OFFLOAD)
		info->offload = IPT_CSUM_NO_OFFLOAD;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
		case O_OVERWRITE_STR:
			parse_string(cb->arg, info);
			break;
		case O_OVERWRITE_HEX:
			parse_hex_string(cb->arg, info);
			break;
		case O_OFFLOAD:
			info->offload = IPT_CSUM_OFFLOAD;
			break;
	}
}

//Ensures that the call to iptables was valid
static void OVERWRITE_check(struct xt_fcheck_call *cb)
{
	if (!(cb->xflags & F_ANY))
		xtables_error(PARAMETER_PROBLEM,
				"OVERWRITE: You must specify --offset and -overwrite-<str/hex>");
	if (!(cb->xflags & (F_OVERWRITE_STR | F_OVERWRITE_HEX)))
		xtables_error(PARAMETER_PROBLEM,
				"OVERWRITE: You must specify `--overwrite-str' or `--overwrite-hex'");
}

//Prints the hex representation of a string
static void print_hex_string(const char *str, const unsigned short int len)
{
	unsigned int i;
	/* start hex block */
	printf(" \"");
	for (i=0; i < len; i++)
		printf("%02x", (unsigned char)str[i]);
	/* close hex block */
	printf("\"");
}

//Test to see if the string contains non-printable chars
static unsigned short int is_hex_string(const char *str, const unsigned short int len)
{
	unsigned int i;
	for (i=0; i < len; i++)
		if (!isprint(str[i]))
			return 1;  // string contains at least one non-printable char
	return 0;
}

//Prints the string and scans for quotes and backslashes
static void print_string(const char *str, const unsigned short int len)
{
	unsigned int i;
	printf(" \"");
	for (i=0; i < len; i++) {
		if (str[i] == '\"' || str[i] == '\\')
			putchar('\\');
		printf("%c", (unsigned char) str[i]);
	}
	printf("\"");  /* closing quote */
}

//Reconstruct and print the parameters for the module in a
//way that can be reimported into iptables
static void OVERWRITE_save(const void *ip, const struct xt_entry_target *target)
{
	const struct ipt_OVERWRITE_info *info = 
		(struct ipt_OVERWRITE_info *) target->data;
	if (is_hex_string(info->pattern, info->patlen)) {
		printf(" --overwrite-hex");
		print_hex_string(info->pattern, info->patlen);
	} else {
		printf(" --overwrite-str");
		print_string(info->pattern, info->patlen);
	}	
	printf(" --offset %u", info->offset);

}

//Print info about what the module is doing
static void OVERWRITE_print(const void *ip, const struct xt_entry_target *target,
		int numeric)
{
	const struct ipt_OVERWRITE_info *info =
		(struct ipt_OVERWRITE_info *) target->data;
	if ( is_hex_string(info->pattern, info->patlen)){
		printf(" OVERWRITE packet[%u:%u] with hex ", info->offset, info->offset + info->patlen);
		print_hex_string(info->pattern, info->patlen);
	} else{
		printf(" OVERWRITE packet[%u:%u] with ", info->offset, info->offset + info->patlen);
		print_string(info->pattern, info->patlen);
	}
}

static struct xtables_target overwrite_tg_reg = {
	.name		= "OVERWRITE",
	.version	= XTABLES_VERSION,
	.family		= NFPROTO_IPV4,
	.size		= XT_ALIGN(sizeof(struct ipt_OVERWRITE_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct ipt_OVERWRITE_info)),
	.help		= OVERWRITE_help,
	.print		= OVERWRITE_print,
	.save		= OVERWRITE_save,
	.x6_parse	= OVERWRITE_parse,
	.x6_fcheck	= OVERWRITE_check,
	.x6_options	= OVERWRITE_opts,
};

void _init(void)
{
	xtables_register_target(&overwrite_tg_reg);
}
