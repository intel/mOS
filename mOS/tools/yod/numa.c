/*
 * Multi Operating System (mOS)
 * Copyright (c) 2018, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "mos_cpuset.h"
#include "yod.h"
#include "yod_debug.h"

#define MIN(x, y) ((x) < (y) ? (x) : (y))

static char *envelope_to_str(envelope_t *e, char *buffer, size_t length)
{
	size_t i;

	buffer[0] = 0;

	STR_APPEND(buffer, length, "CPUs=%s ",
		   mos_cpuset_to_list_validate(e->cpus));

	STR_APPEND(buffer, length, "GPUs=%s NIDs=",
		   mos_cpuset_to_list_validate(e->gpus));

	for (i = 0; i < e->n_nids; i++)
		STR_APPEND(buffer, length, "%zd,", e->nids[i]);
	STR_APPEND(buffer, length, " [%zd]", e->n_nids);

	return buffer;
}

#define ENVEL2STR(e, b) envelope_to_str(e, b, sizeof(b))

/**
 * Compare two envelopes.
 */
static bool envelope_equals(envelope_t *e1, envelope_t *e2)
{
	size_t i;

	if (!mos_cpuset_equal(e1->cpus, e2->cpus))
		return false;

	if (e1->n_nids != e2->n_nids)
		return false;

	for (i = 0; i < e1->n_nids; i++)
		if (e1->nids[i] != e2->nids[i])
			return false;

	return true;
}

/**
 * Create an empty and loose envelope.
 */
static envelope_t *new_envelope(void)
{
	envelope_t *e = malloc(sizeof(envelope_t));

	if (!e)
		yod_abort(-ENOMEM, "Out of memory");

	e->cpus = mos_cpuset_alloc_validate();
	e->gpus = mos_cpuset_alloc_validate();
	e->n_nids = 0;
	e->next = 0;

	return e;
}

/**
 * Compute the available memory for the given NID.  We must account for both
 * the amount already reserved by other processes as well as any memory that
 * has already been set aside for the request under construction.
 */

static size_t mem_available(size_t nid, struct lwk_request_t *req)
{
	return req->lwkmem_designated[nid] -
		req->lwkmem_reserved[nid] -
		req->lwkmem_request[nid];
}

static enum mem_group_t _nid_to_mem_grp(int nid)
{
	enum mem_group_t g = yod_nid_to_mem_group(nid);

	if (g == YOD_MEM_GROUP_UNKNOWN)
		yod_abort(-EINVAL, "NID %d is unknown.", nid);

	return g;
}

/**
 * Construct an envelope of a given depth starting from the given NID.
 * @param[in] nid The starting point from which the envelope will be created.
 * @param[in] depth The depth of the envelope, i.e. the number of (unique)
 *     distances to be used from the ordered set of distances.
 * @param[in] req The request object.
 * @return An envelope object properly populated with its CPU mask and list
 *     of NIDs.  The envelope is not chained (ret->next is NULL).
 */

static envelope_t *construct_envelope(size_t nid, size_t depth,
				      lwk_request_t *req)
{
	envelope_t *envelope = new_envelope();
	size_t i, j, dist[YOD_MAX_NIDS], N;
	enum mem_group_t m;
	struct map_type_t *node_map, *node_map_gpu;
	char str[512];

	YOD_LOG(YOD_GORY,
		"(>) %s nid=%zd depth=%zd",
		__func__,
		nid,
		depth);

	N = ARRAY_SIZE(dist);
	req->plugin->get_distance_map(nid, dist, &N);
	node_map = yod_get_map(YOD_NODE);
	node_map_gpu = yod_get_map(YOD_NODE_GPU);

	for (i = 0; i < req->n_nids; i++) {

		m = _nid_to_mem_grp(i);

		for (j = 0; j < depth + 1; j++) {

			if (dist[i] != req->dist_by_type[m][j])
				continue;

			if (node_map->map[i])
				mos_cpuset_or(envelope->cpus, envelope->cpus,
					      node_map->map[i]);
			if (node_map_gpu->map[i])
				mos_cpuset_or(envelope->gpus, envelope->gpus,
					      node_map_gpu->map[i]);

			envelope->nids[envelope->n_nids++] = i;

			break;
		}
	}

	YOD_LOG(YOD_GORY,
		"(<) %s envelope=%s",
		__func__,
		ENVEL2STR(envelope, str));

	return envelope;
}

static void construct_numa_distance_sets(lwk_request_t *req)
{
	struct map_type_t *node_map;
	size_t i, j, dist[YOD_MAX_NIDS], N;
	enum mem_group_t m;

	node_map = yod_get_map(YOD_NODE);

	/* Construct ordered sets of distances, indexed by memory type.  Only
	 * distances from nodes with CPUs are considered.
	 */

	memset(&req->dist_by_type_len, 0, sizeof(req->dist_by_type_len));

	for (i = 0; i < req->n_nids; i++) {

		if (yod_null_map(node_map, i))
			continue;

		N = ARRAY_SIZE(dist);
		req->plugin->get_distance_map(i, dist, &N);

		for (j = 0; j < N; j++) {
			m = _nid_to_mem_grp(j);
			yod_ordered_set_insert(req->dist_by_type[m],
			       dist[j],
			       &req->dist_by_type_len[m],
			       ARRAY_SIZE(req->dist_by_type[m]));
		}
	}

	/* Count and validate the distances sets.  For systems with multiple
	 * types of memory, we expect the size of these sets to be uniform
	 * across memory types.
	 */

	req->n_partitions = 0;

	for (m = 0; m < YOD_NUM_MEM_GROUPS; m++) {

		if (!req->dist_by_type_len[m])
			continue;

		if (!req->n_partitions)
			req->n_partitions = req->dist_by_type_len[m];

		if (req->n_partitions != req->dist_by_type_len[m])
			yod_abort(-EINVAL,
				  "Inconsistent memory hierarchy data. Type %d has %zd unique distances (expected %zd)",
				  m, req->dist_by_type_len[m],
				  req->n_partitions);
	}
}

static int construct_envelopes(lwk_request_t *req)
{
	size_t lvl, j;
	struct map_type_t *node_map;
	envelope_t *envelope, *head;
	char str[512];

	YOD_LOG(YOD_DEBUG, "(>) %s", __func__);

	node_map = yod_get_map(YOD_NODE);

	/* Construct the envelopes making up the partition for each depth. */

	for (lvl = 0; lvl < req->n_partitions; lvl++) {

		YOD_LOG(YOD_DEBUG,
			"(*) [%s] Constructing level %zd of %zd envelope partitions.",
			__func__,
			lvl,
			req->n_partitions);

		req->partition[lvl] = NULL;

		for (j = 0; j < req->n_nids; j++) {

			if (yod_null_map(node_map, j))
				continue;

			envelope = construct_envelope(j, lvl, req);

			if (!mos_cpuset_cardinality(envelope->cpus)) {
				free(envelope);
				continue;
			}

			if (!req->partition[lvl]) {
				req->partition[lvl] = envelope;
				YOD_LOG(YOD_DEBUG,
					"(*) [%s] Added envelope: %s",
					__func__,
					ENVEL2STR(envelope, str));
				continue;
			}

			for (head = req->partition[lvl]; head && envelope; ) {
				if (envelope_equals(envelope, head)) {
					YOD_LOG(YOD_GORY,
						"(*) [%s] Duplicate: %s",
						 __func__,
						ENVEL2STR(envelope, str));
					free(envelope);
					envelope = NULL;
				} else if (!head->next) {
					head->next = envelope;
					head = NULL;
					YOD_LOG(YOD_DEBUG,
						"(*) [%s] Added envelope: %s",
						__func__,
						ENVEL2STR(envelope, str));
				} else {
					head = head->next;
				}
			}
		}
	}

	return -1;
}

static int indirect_numa_memory_selection(struct lwk_request_t *req)
{
	envelope_t *e;
	mos_cpuset_t *cpus = mos_cpuset_alloc_validate();
	char str[512];
	size_t i, nid, requested, available, n_cpus_requested;
	enum mem_group_t m;
	double ratio;
	size_t by_group[YOD_NUM_MEM_GROUPS] = {0, };
	bool incomplete;

	YOD_LOG(YOD_GORY,
		"(>) %s",
		__func__);

	if (req->n_partitions == 0) {
		construct_numa_distance_sets(req);
		construct_envelopes(req);
	}

	/* We arrived here via a path that did *NOT* involve the core selection
	 * algorithm (above).  However, CPUs have already been selected and
	 * are available via the lwkcpus_request mask.  Attempt to select
	 * memory from various domains in proportion to the selected CPUs
	 * in those domains.
	 *
	 * Step 1: Use the level 0 envelopes to perform the idealized
	 *         fit:
	 */

	n_cpus_requested = mos_cpuset_cardinality(req->lwkcpus_request);

	for (e = req->partition[0]; e; e = e->next) {

		mos_cpuset_and(cpus, e->cpus, req->lwkcpus_request);

		if (mos_cpuset_is_empty(cpus))
			continue;

		ratio =	(double)mos_cpuset_cardinality(cpus) / n_cpus_requested;

		YOD_LOG(YOD_DEBUG,
			"(*) [%s] pass 1 : envelope:%s ratio:%f",
			__func__,
			ENVEL2STR(e, str),
			ratio);

		for (i = 0; i < e->n_nids; i++) {

			nid = e->nids[i];
			m = _nid_to_mem_grp(nid);

			if (by_group[m] == 0)
				by_group[m] = req->lwkmem_size_by_group[m];

			requested = (size_t)(ratio * by_group[m]);
			available = mem_available(nid, req);

			requested = MIN(requested, available);

			YOD_LOG(YOD_DEBUG,
				"(*) [%s] pass 1: group:%s size:%zd requestd:%zd available:%zd",
				__func__,
				MEM_GROUPS[m],
				req->lwkmem_size_by_group[m],
				requested,
				available);

			req->lwkmem_request[nid] = requested;
			req->lwkmem_size_by_group[m] -= requested;
			if (requested)
				yod_append_memory_nid(m, nid, req);
		}
	}

	incomplete = false;

	for (m = 0; m < YOD_NUM_MEM_GROUPS; m++) {
		incomplete |= (req->lwkmem_size_by_group[m] != 0);
		YOD_LOG(YOD_DEBUG,
			"(*) [%s] group:=%s remaining:%zd",
			__func__,
			MEM_GROUPS[m],
			req->lwkmem_size_by_group[m]);
	}

	if (!incomplete)
		goto out;

	/* Step 2: If we got here, there is still more memory to be reserved.
	 * And so walk the nodes in order to complete the request.
	 */

	for (nid = 0; nid < req->n_nids; nid++) {

		m = _nid_to_mem_grp(nid);

		requested = req->lwkmem_size_by_group[m];
		available = mem_available(nid, req);

		if (!requested || !available)
			continue;

		requested = MIN(requested, available);

		YOD_LOG(YOD_DEBUG,
			"(*) [%s] pass 2: nid:%zd group:%s size:%zd  requested:%zd available:%zd",
			__func__,
			nid,
			MEM_GROUPS[m],
			req->lwkmem_size_by_group[m],
			requested,
			available);

		req->lwkmem_request[nid] += requested;
		req->lwkmem_size_by_group[m] -= requested;
		if (requested)
			yod_append_memory_nid(m, nid, req);
	}

	incomplete = false;

	for (m = 0; m < YOD_NUM_MEM_GROUPS; m++) {
		incomplete |= (req->lwkmem_size_by_group[m] != 0);
		YOD_LOG(YOD_DEBUG, "(*) [%s] grp=%s rem=%zd",
			__func__, MEM_GROUPS[m], req->lwkmem_size_by_group[m]);
	}

 out:

	mos_cpuset_free(cpus);

	YOD_LOG(YOD_DEBUG, "(<) %s rc=%d", __func__, incomplete ? -1 : 0);

	return incomplete ? -1 : 0;
}

int yod_numa_compute_core_algorithm(struct lwk_request_t *req, size_t n_cores,
				    mos_cpuset_t *available)
{
	envelope_t *e;
	char buff[512];
	mos_cpuset_t *maybe = mos_cpuset_alloc_validate();
	mos_cpuset_t *preselected_gpus = NULL;
	mos_cpuset_t *temp_gpus = NULL;
	size_t i, nid, lvl, avail_mem[YOD_NUM_MEM_GROUPS];
	enum mem_group_t m;
	bool fits;

	YOD_LOG(YOD_DEBUG,
		"(>) [%s] n_cores=%zd available=%s",
		__func__,
		n_cores,
		mos_cpuset_to_list_validate(available));

	construct_numa_distance_sets(req);
	construct_envelopes(req);

	/* Are GPUs being selected by a caller-supplied ZE_AFFINITY_MASK? */
	if (req->ze_affinity_on_entry && !req->explicit_gpus_request) {

		preselected_gpus = mos_cpuset_alloc_validate();
		temp_gpus = mos_cpuset_alloc_validate();
		yod_ze_mask_to_mos_gpuset(req->ze_affinity_on_entry, preselected_gpus);
	}

	for (lvl = 0; lvl < req->n_partitions; lvl++) {

		for (e = req->partition[lvl]; e; e = e->next) {

			/* Test 1: are there enough available LWK cores in this
			 * envelope?
			 */

			mos_cpuset_and(maybe, available, e->cpus);

			YOD_LOG(YOD_GORY,
				"(*) [%s] Testing available cores: level:%zd envelope %s => %s (%zd cores)",
				__func__,
				lvl,
				ENVEL2STR(e, buff),
				mos_cpuset_to_list_validate(maybe),
				yod_count_by(maybe, YOD_CORE));

			if (yod_count_by(maybe, YOD_CORE) < (ssize_t)n_cores)
				continue;

			/* Test 2: Are any pre-selected GPUs in this envelope? */

			if (preselected_gpus) {
				mos_cpuset_and(temp_gpus, e->gpus, preselected_gpus);
				if (mos_cpuset_is_empty(temp_gpus))
					continue;
			}

			/* Test 3: is there enough available LWK memory in
			 * this envelope?
			 */

			memset(avail_mem, 0, sizeof(avail_mem));

			for (i = 0; i < e->n_nids; i++) {
				nid = e->nids[i];
				avail_mem[_nid_to_mem_grp(nid)] +=
					mem_available(nid, req);
			}

			fits = true;

			for (m = 0; m < YOD_NUM_MEM_GROUPS && fits; m++) {

				fits = req->lwkmem_size_by_group[m] <= avail_mem[m];

				YOD_LOG(YOD_GORY,
					"(*) [%s] Testing available memory: level:%zd type:%s available::%zd need:%zd fits:%d",
					__func__,
					lvl,
					MEM_GROUPS[m],
					avail_mem[m],
					req->lwkmem_size_by_group[m],
					fits);

			}

			if (!fits)
				continue;

			/* Selected the first N cores from the envelope, storing
			 * them into the lwkcpus_request buffer.  And also stash
			 * the envelope into request state so that we can grab
			 * the corresponding memory later.
			 */

			YOD_LOG(YOD_DEBUG,
				"(*) [%s] Request fits in level:%zd envelope:%s",
				__func__,
				lvl,
				ENVEL2STR(e, buff));

			yod_select_by(n_cores, YOD_CORE, true, false, maybe,
				      req->lwkcpus_request);
			req->selected_envelope = e;

			mos_cpuset_free(maybe);
			if (preselected_gpus) {
				mos_cpuset_free(preselected_gpus);
				mos_cpuset_free(temp_gpus);
			}

			YOD_LOG(YOD_DEBUG,
				"(<) %s",
				__func__);

			return 0;
		}
	}

	show_state(YOD_CRIT);
	yod_abort(-EBUSY, "Insufficient LWK resources.");
}

int yod_numa_memory_selection_algorithm(lwk_request_t *req)
{
	size_t i, have, rqst, nid;
	enum mem_group_t m;

	/* If we have have arrived here without going through the core selection
	 * algorithm (above).  In such a case, we will try to select memory
	 * from the envelope(s) containing the requested CPUs:
	 */

	if (!req->selected_envelope)
		return indirect_numa_memory_selection(req);

	/* Otherwise, walk the NIDs in the envelope that was used to reserve
	 * the CPUs.  We already know that there is enough memory to complete
	 * the request.
	 */
	for (i = 0; i < req->selected_envelope->n_nids; i++) {

		nid = req->selected_envelope->nids[i];
		m = _nid_to_mem_grp(nid);

		have = mem_available(nid, req);
		rqst = MIN(req->lwkmem_size_by_group[m], have);

		YOD_LOG(YOD_GORY,
			"Request memory: nid=%zd (%s) available=%zd want=%zd remaining=%zd",
			nid, MEM_GROUPS[m], have,
			req->lwkmem_size_by_group[m],
			req->lwkmem_size_by_group[m] - rqst);

		if (!rqst)
			continue;

		req->lwkmem_request[nid] = rqst;
		req->lwkmem_size_by_group[m] -= rqst;
		if (rqst)
			yod_append_memory_nid(m, nid, req);
	}
	return 0;
}

/* Look into the lwk_request object to see what NIDs are being
 * requested. Based on the NIDs, construct a mask of the GPUs attached
 * to those NIDs. Uses this candidate list and the explicit user GPU
 * requests, determine the GPUs for reservation.
 */
int yod_numa_gpu_selection_algorithm(lwk_request_t *req,
					size_t num_gpus,
					bool device,
					mos_cpuset_t *availgpus)
{
	int nid, mtype;
	size_t i, num_selected;
	struct map_type_t *node_map;
	mos_cpuset_t *candidates = mos_cpuset_alloc_validate();

	node_map = yod_get_map(YOD_NODE_GPU);

	/* Find the list of NIDs that are being requested and construct the
	 * list of GPU devices that exist in those numa domains
	 */
	for (mtype = 0;  mtype < YOD_NUM_MEM_GROUPS; mtype++) {
		for (i = 0; i < req->lwkmem_domain_info_len[mtype]; i++) {
			nid = req->lwkmem_domain_info[mtype][i];
			if (nid < YOD_MAX_NIDS && node_map->map[nid])
				mos_cpuset_or(candidates,
					      candidates,
					      node_map->map[nid]);
		}
	}
	mos_cpuset_and(candidates, candidates, availgpus);

	/* Process the usage counts for the available GPUs and starting with
	 * the lowest usage count, select gpus until we reach num_gpus
	 * store this bit mask in the request object so later it can be
	 * requested/processed
	 */
	yod_balanced_gpu_select(num_gpus, device, candidates, req->lwkgpus_request);

	/* If The requested number of GPUs is less than the number of GPUs
	 * in the original candidates list, we will need to also look outside of
	 * this set of devices (i.e. outside of the numa domains being used by
	 * the memory and CPUs). Include these these additional devices
	 * only after we have exhausted the primary candidates.
	 */
	num_selected = mos_cpuset_cardinality(req->lwkgpus_request);
	if (device)
		num_selected = num_selected / yod_get_num_tiles_per_gpu();

	if (num_gpus  > num_selected) {
		yod_get_designated_lwkgpus(candidates);
		mos_cpuset_xor(candidates, candidates, req->lwkgpus_request);
		yod_balanced_gpu_select(num_gpus - num_selected, device, candidates,
				    req->lwkgpus_request);
	}
	mos_cpuset_free(candidates);

	return 0;
}

