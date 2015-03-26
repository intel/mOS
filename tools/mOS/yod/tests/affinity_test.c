#define HAVE_DECL_CPU_ALLOC 1
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <locale.h>

#include "cpuset.h"

#define STARTS_WITH(s, prefix) (strncmp(s, prefix, strlen(prefix)) == 0)

static size_t setsize;
static size_t nbits;
static int max_cpus;

void usage()
{
	printf("affinity-test [--affinity <mask|list>] [--echo] [--commas]\n");
	printf("  [--lwkmem_reserved <value>] [--lwkcpus_reserved <mask|list>]\n");
	printf("  [--utilcpus_reserved <mask|list>]\n");
	printf("  [--wait-for <file> [--no-unlink]]\n");
	printf("  %-16s : Specifies the expected affinity.\n", "--affinity");
	printf("  %-16s : Print the affinity.\n", "--echo");
	printf("  %-16s : Use commas when showing masks.\n", "--commas");
	printf("  %-16s : Specifies the expected lwkmem_reserved value.\n", "--lwkmem_reserved");
	printf("  %-16s : Specifies the expected lwkcpus_reserved value.\n", "--lwkcpus_reserved");
	printf("  %-16s : Specifies the expected utilcpus_reserved value.\n", "--utilcpus_reserved");
	exit(-1);
}

char *cpu_mask(cpu_set_t *set, char *buff, size_t len, int commas)
{
	char *bp = buff;

	cpumask_create(buff, len, set, setsize);

	/* Eliminate leading zeroes (except for the empt set case) */

	if (strlen(buff) > 1) {
		while (*bp == '0') {
			bp++;
		}
	}

	/* If requested, insert commas between every 32-bit piece
	 * of the mask */

	if (commas && strlen(bp) > 8) {

		char tmp[1024];
		char *tp = tmp;
		int n = strlen(bp) % 8;

		do {
			strncpy(tp, bp, n);
			tp += n;
			*(tp++) = ',';
			bp += n;
			n = strlen(bp) ? 8 : 0;
		} while (n);

		/* strip off the trailing comma */
		tp--;
		*tp = 0;

		strcpy(buff, tmp);
		bp = buff;
	}

	return bp;
}

void parse_cpuset(const char *arg, cpu_set_t *set)
{
	int rc;

	if (STARTS_WITH(arg, "0x") || STARTS_WITH(arg, "0X")) {
		rc = cpumask_parse(arg, set, setsize);
	} else {
		rc = cpulist_parse(arg, set, setsize);
	}

	if (rc) {
		fprintf(stderr, "ERROR: could not parse CPU set: %s\n", arg);
		exit(-1);
	}
}

void show_cpuset(cpu_set_t *set, const char *label, int use_commas)
{
	char buff1[4096], buff2[4096];

	printf("[%d] %-32s | %20s | %s\n",
	       getpid(),
	       label,
	       cpu_mask(set, buff1, sizeof(buff1), use_commas),
	       cpulist_create(buff2, sizeof(buff2), set, setsize)
	       );
}

int get_sysfs_data(char *buffer, size_t len, const char *sysfsn)
{
	char fname[4096];
	FILE *f;
	int rc;

	if (getenv("YOD_TST_PLUGIN")) {
		sprintf(fname, "/tmp/%s/yod/%s", getenv("USER"), sysfsn);
	} else {
		sprintf(fname, "/sys/kernel/mOS/%s", sysfsn);
	}

	f = fopen(fname, "r");
	if (!f) {
		printf("(E) opening %s : %s\n", fname, strerror(errno));
		exit(-1);
	}

	rc = fread(buffer, 1, len, f);

	if (rc < 0) {
		printf("(E) reading %s : %s\n", fname, strerror(errno));
		exit(-1);
	}

	buffer[rc] = 0;
	fclose(f);

	return rc;
}

void get_sysfs_cpuset(cpu_set_t *set, const char *sysfsn)
{
	char buffer[4096];
	int rc;

	rc = get_sysfs_data(buffer, sizeof(buffer), sysfsn);

	if ((rc == 0) || (buffer[0] == '\n') || (buffer[0] == ' ')) {
		CPU_XOR_S(setsize, set, set, set);
	} else {
		rc = cpulist_parse(buffer, set, setsize);
		if (rc) {
			printf("(E) Could not parse CPU set \"%s\"\n", buffer);
			exit(-1);
		}
	}
}

int compare_cpusets(cpu_set_t *a, cpu_set_t *b, const char *label)
{
	char lbl[4096];
	cpu_set_t *diff = cpuset_alloc(max_cpus, &setsize, &nbits);
	int rc;

	printf("\n");
	sprintf(lbl, "expected %s", label);
	show_cpuset(a, lbl, 0);
	sprintf(lbl, "actual   %s", label);
	show_cpuset(b, lbl, 0);

	CPU_XOR_S(setsize, diff, a, b);

	if (CPU_EQUAL_S(setsize, a, b)) {
		strcpy(lbl, "match!");
		rc = 0;
	} else {
		strcpy(lbl, "MISMATCH!");
		rc = -1;
	}
	show_cpuset(diff, lbl, 0);
	return rc;
}

size_t split(char *s, const char *delim, size_t *list, size_t capacity)
{
	char *loc, *save, *remainder, *tok;
	int rc;
	char *copy;

	loc = copy = strdup(s);
	rc = 0;

	while ((tok = strtok_r(loc, delim, &save)) != 0) {

		if (rc == capacity) {
			fprintf(stderr, "OVERFLOW!\n");
			rc = -1;
			goto out;
		}

		list[rc++] = strtoul(tok, &remainder, 0);

		if (*remainder != '\0') {
			fprintf(stderr, "ERROR: garbage detected in list \"%s\" at offset %ld\n", s, remainder - copy);
			rc = -1;
			goto out;
		}

		loc = NULL;
	}

 out:
	free(copy);
	return rc;
}

int compare_memsize(size_t expected, size_t actual, const char *label)
{
	int rc = 0;
	int pid = getpid();

	printf("[%d] %s EXPECTED : 0x%016lX  |  %'ld\n", pid, label, expected, expected);
	printf("[%d] %s ACTUAL   : 0x%016lX  |  %'ld\n", pid, label, actual, actual);
	if (expected != actual) {
		/* The lwkmem subsystem may round reservations down to a
		 * 2M boundary.  Note: 2m = (2**21).
		 */
		if ((expected >> 21) == (actual >> 21)) {
			printf("[%d] %s 2MiB rounding error ... OK\n", pid, label);
		} else {
			printf("[%d] %s MISMATCH!\n", pid, label);
			rc--;
		}
	} else {
		printf("[%d] %s match!\n", pid, label);
	}
	return rc;
}

int compare_lwkmem(char *expected, char *actual)
{
	/* If expected is a comma delimited, we will compare
	 * element-for-element.  Otherwise, compare the
	 * single value against the aggregated actual
	 * results.  If expected is NULL, we are in echo
	 * mode.
	 */

	const int LISTSIZE = 256;
	size_t lene, lena;
	size_t liste[LISTSIZE], lista[LISTSIZE];
	int i, rc = 0;

	lene = split(expected ? expected : "0", ",\n", liste, LISTSIZE);
	lena = split(actual, " \n", lista, LISTSIZE);

	printf("\n");

	if (lene == 1) {
		size_t actual_total = 0;

		for (i = 0; i < lena; i++)
			actual_total += lista[i];

		rc += compare_memsize(liste[0], actual_total, "lwkmem_reserved[*]");
	} else {

		if (lene != lena)
			printf("MISMATCHED lwkmem_reserved lists! %ld vs %ld\n", lene, lena);

		for (i = 0; i < lene; i++) {
			char label[64];

			sprintf(label, "lwkmem_reserved[%d]", i);
			rc += compare_memsize(liste[i], lista[i], label);
		}
	}

	return expected ? rc : 0;
}

int main(int argc, char **argv)
{
	int i;
	
	cpu_set_t
		*exp_affinity = 0,
		*act_affinity = 0,
		*act_lwkcpus_rsvd = 0,
		*exp_lwkcpus_rsvd = 0,
		*act_utilcpus_rsvd = 0,
		*exp_utilcpus_rsvd = 0;

	int echo_only = 0;
	int use_commas = 0;
	char *lwkmem_rsvd = 0;
	int rc = 0;
	char *wait_for = 0;
	int do_unlink = 1;

	setlocale(LC_ALL, "");

	if (getenv("YOD_MAX_CPUS"))
		max_cpus = atoi(getenv("YOD_MAX_CPUS"));
	else
		max_cpus = get_max_number_of_cpus();

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--affinity") == 0) {
			exp_affinity =
				cpuset_alloc(max_cpus, &setsize, &nbits);
			parse_cpuset(argv[++i], exp_affinity);
		} else if (strcmp(argv[i], "--lwkcpus_reserved") == 0) {
			exp_lwkcpus_rsvd =
				cpuset_alloc(max_cpus, &setsize, &nbits);
			parse_cpuset(argv[++i], exp_lwkcpus_rsvd);
		} else if (strcmp(argv[i], "--utilcpus_reserved") == 0) {
			exp_utilcpus_rsvd =
				cpuset_alloc(max_cpus, &setsize, &nbits);
			parse_cpuset(argv[++i], exp_utilcpus_rsvd);
		} else if (strcmp(argv[i], "--echo") == 0) {
			echo_only = 1;
		} else if (strcmp(argv[i], "--commas") == 0) {
			use_commas = 1;
		} else if (strcmp(argv[i], "--lwkmem_reserved") == 0) {
			lwkmem_rsvd = strdup(argv[++i]);
		} else if (strcmp(argv[i], "--wait-for") == 0) {
			wait_for = argv[++i];
		} else if (strcmp(argv[i], "--no-unlink") == 0) {
			do_unlink = 0;
		} else {
			usage();
			exit(0);
		}
	}

	if (!exp_affinity && !exp_lwkcpus_rsvd && !exp_utilcpus_rsvd && lwkmem_rsvd && !echo_only) {
		fprintf(stderr, "ERROR: At least one of {--affinity, --lwkcpus_reserved, --utilcpus_reserved, --lwkmem_reserved, --echo} must be specified\n");
		exit(-1);
	}

	if (wait_for) {
		printf("[%d] Waiting for %s ... \n", getpid(), wait_for);
		fflush(stdout);
		do {
			FILE *f = fopen(wait_for, "r");
			if (!f) {
				sleep(1);
			} else {
				fclose(f);
				if (do_unlink && unlink(wait_for))
					printf("problems unlinking: %s\n", strerror(errno));
				wait_for = 0;
			}
		} while (wait_for);
	}

	act_affinity = cpuset_alloc(max_cpus, &setsize, &nbits);

	if (sched_getaffinity(0, setsize, act_affinity)) {
		fprintf(stderr, "ERROR: could not get my own affinity\n");
		exit(-1);
	}

	act_lwkcpus_rsvd = cpuset_alloc(max_cpus, &setsize, &nbits);
	act_utilcpus_rsvd = cpuset_alloc(max_cpus, &setsize, &nbits);

	get_sysfs_cpuset(act_lwkcpus_rsvd, "lwkcpus_reserved");
	get_sysfs_cpuset(act_utilcpus_rsvd, "utilcpus_reserved");

	if (echo_only) {
		show_cpuset(act_affinity, "actual affinity", use_commas);
		show_cpuset(act_lwkcpus_rsvd, "lwkcpus_reserved", use_commas);
		show_cpuset(act_utilcpus_rsvd, "utilcpus_reserved", use_commas);
		exit(0); /* we are done */
	}

	if (exp_affinity && compare_cpusets(exp_affinity, act_affinity, "affinity"))
		rc--;

	if ((exp_lwkcpus_rsvd) &&
	    compare_cpusets(exp_lwkcpus_rsvd, act_lwkcpus_rsvd,
			    "lwkcpus_reserved"))
		rc--;

	if ((exp_utilcpus_rsvd) &&
	    compare_cpusets(exp_utilcpus_rsvd, act_utilcpus_rsvd,
			    "utilcpus_reserved"))
		rc--;

	if (lwkmem_rsvd || echo_only) {

		char buffer[4096];
		
		get_sysfs_data(buffer, sizeof(buffer), "lwkmem_reserved");

		if (compare_lwkmem(lwkmem_rsvd, buffer))
			rc--;
	}


	if (rc)
		printf("Test failed!\n");

	exit(rc);
}
