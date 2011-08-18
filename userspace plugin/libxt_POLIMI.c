/* Shared library add-on to iptables to add POLIMI target support. 
Ex. Usage:
	iptables -t mangle -A INPUT -t POLIMI --findstring badstring --replacestring goodstring
*/

#include <linux/netfilter/xt_POLIMI.h>
#include <string.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <ctype.h>
#include <xtables.h>


/*
	Help Function ( --help)
*/
static void
polimi_help(void)
{
	printf("POLIMI target options:\n"
	       " --findString String to replace\n"
	       " --replaceString Replacing string\n"
	       );
}
/*
	Description of actions (iptables -L)
*/
static void polimi_print(const void *ip, const struct xt_entry_target *target,
                      int numeric)
{
	const struct xt_polimi_info *myinfo
		= (const struct xt_polimi_info *)target->data;
	printf("\n POLIMI TARGET: Replace '%s' with '%s'",myinfo->findString,myinfo->replString);
}
/*
	Parameters
*/
static const struct option polimi_opts[] = {
	{.name = "findstring", .has_arg = true,  .val = 'f'},
	{.name = "replacestring", .has_arg = true,  .val = 'r'},
	XT_GETOPT_TABLEEND,
};

/*	
	Parameters Validation
*/
static void polimi_check(unsigned int flags)
{
	if (flags!=3)
		xtables_error(PARAMETER_PROBLEM,
			   "You must specify both parameters and there can't be duplicates!");
	
}

/*
	Parameters Parsing
*/
static int polimi_parse(int c, char **argv, int invert, unsigned int *flags,
		    const void *entry, struct xt_entry_target **target)
{
	struct xt_polimi_info *myinfo =
		(struct xt_polimi_info *) (*target)->data;
	

	switch (c) {
	case 'f':		/* --findString <string>*/
		if(strlen(optarg)>POLIMI_TARGET_MAX_STRING_SIZE)
			xtables_error(PARAMETER_PROBLEM,
			   "findstring too long");

		strcpy(myinfo->findString,optarg);
		myinfo->find_len=strlen(optarg);
		*flags=*flags+1;
		
		break;
	case 'r':		/* --replaceString <string> */
		if(strlen(optarg)>POLIMI_TARGET_MAX_STRING_SIZE)
			xtables_error(PARAMETER_PROBLEM,
			   "replacestring too long");
		strcpy(myinfo->replString,optarg);
		myinfo->repl_len=strlen(optarg);
		*flags=*flags+2;

		break;
	}
	return 1;
}

static struct xtables_target polimi_target = {

	.name          = "POLIMI",
	.version       = XTABLES_VERSION,
	.family        = NFPROTO_IPV4,
	.size          = XT_ALIGN(sizeof(struct xt_polimi_info)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_polimi_info)),
	.help          = polimi_help,
	.final_check   = polimi_check,
	.print         = polimi_print,
	.parse         = polimi_parse,
	.extra_opts    = polimi_opts,

};

void _init(void)
{
	xtables_register_target(&polimi_target);
}
