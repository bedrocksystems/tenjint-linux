/*
 * KVM VMI support
 *
 * Copyright (C) 2017 FireEye, Inc. All Rights Reserved.
 *
 * Authors:
 *  Jonas Pfoh      <jonas.pfoh@fireeye.com>
 *  Sebastian Vogl  <sebastian.vogl@fireeye.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

#include <linux/kvm_vmi.h>

#include "vmi.h"

struct vmi_dtb_entry{
	struct hlist_node list;
	u64 dtb;
	bool in;
	bool out;
};

struct kvm_vmi_slp_node {
	struct hlist_node h;
	u32 count;
	u64 gfn;
};

void kvm_vmi_vcpu_init(struct kvm_vcpu *vcpu)
{
	hash_init(vcpu->arch.vmi_dtb_ht);
	hash_init(vcpu->arch.vmi_slp_ht);
}

void kvm_vmi_vcpu_uninit(struct kvm_vcpu *vcpu)
{
	int i;
	struct hlist_node *tmp;
	struct vmi_dtb_entry *dtb_entry;
	struct kvm_vmi_slp_node *slp_node;

	hash_for_each_safe (vcpu->arch.vmi_dtb_ht, i, tmp, dtb_entry, list) {
		hash_del(&dtb_entry->list);
		kfree(dtb_entry);
	}

	hash_for_each_safe(vcpu->arch.vmi_slp_ht, i, tmp, slp_node, h) {
		hash_del(&(slp_node->h));
		kfree(slp_node);
	}
}

static struct vmi_dtb_entry* kvm_vmi_dtb_get_entry(struct kvm_vcpu *vcpu, u64 dtb)
{
	struct vmi_dtb_entry *entry;

	hash_for_each_possible(vcpu->arch.vmi_dtb_ht,entry,list,dtb){
		if(entry->dtb == dtb)
			return entry;
	}
	return NULL;
}

static void kvm_vmi_dtb_rm_entry(struct kvm_vcpu *vcpu, u64 dtb)
{
	struct hlist_node *tmp;
	struct vmi_dtb_entry *entry;

	hash_for_each_possible_safe(vcpu->arch.vmi_dtb_ht,entry,tmp,list,dtb){
		if(entry->dtb == dtb){
			hash_del(&entry->list);
			kfree(entry);
			return;
		}
	}
	return;
}

static void kvm_vmi_dtb_add_update_entry(struct kvm_vcpu *vcpu, u64 dtb, bool in, bool out)
{
	struct vmi_dtb_entry *entry;
	struct vmi_dtb_entry *_entry;

	entry = _entry = kvm_vmi_dtb_get_entry(vcpu,dtb);
	if(!entry){
		entry = kzalloc(sizeof(struct vmi_dtb_entry),GFP_KERNEL);
		if(entry == NULL){
			kvm_vmi_error("no memory %p \n",entry);
			return;
		}
	}

	entry->dtb = dtb;
	entry->in = in;
	entry->out = out;

	if(!_entry){
		hash_add(vcpu->arch.vmi_dtb_ht,&entry->list,dtb);
	}
}

bool kvm_vmx_task_switch_need_stop(struct kvm_vcpu *vcpu, u64 cr3_out, u64 cr3_in)
{
	struct vmi_dtb_entry *entry;

	if(cr3_out == cr3_in)
		return false;

	entry = kvm_vmi_dtb_get_entry(vcpu,0);
	if(entry)
		return true;

	entry = kvm_vmi_dtb_get_entry(vcpu,cr3_out);
	if(entry && entry->out)
		return true;

	entry = kvm_vmi_dtb_get_entry(vcpu,cr3_in);
	if(entry && entry->in)
		return true;

	return false;
}

bool vmx_vmi_slp_need_stop(struct kvm_vcpu *vcpu, u64 gpa, bool read_fault,
                             bool write_fault, bool exec_fault) {
	struct kvm_vmi_slp_node *i;
	u64 gfn = gpa >> PAGE_SHIFT;

	if (read_fault && vcpu->arch.vmi_slp_global[KVM_VMI_SLP_R_INDEX]) {
		return true;
	}
	else if (write_fault && vcpu->arch.vmi_slp_global[KVM_VMI_SLP_W_INDEX]) {
		return true;
	}
	else if (exec_fault && vcpu->arch.vmi_slp_global[KVM_VMI_SLP_X_INDEX]) {
		return true;
	}

	hash_for_each_possible(vcpu->arch.vmi_slp_ht, i, h, gfn) {
		if (i->gfn == gfn)
			return true;
	}

	return false;
}

void vmx_vmi_enable_task_switch_trapping(struct kvm_vcpu *vcpu)
{
	u32 exec_ctls = vmx_vmi_get_execution_controls();
	exec_ctls |= CPU_BASED_CR3_LOAD_EXITING;
	vmx_vmi_update_execution_controls(exec_ctls);
}

void vmx_vmi_disable_task_switch_trapping(struct kvm_vcpu *vcpu)
{
	u32 exec_ctls = vmx_vmi_get_execution_controls();
	exec_ctls &= ~CPU_BASED_CR3_LOAD_EXITING;
	vmx_vmi_update_execution_controls(exec_ctls);
}

int vmx_vmi_feature_control_task_switch(struct kvm_vcpu *vcpu, union kvm_vmi_feature *feature)
{
	struct kvm_vmi_feature_task_switch *ts = (struct kvm_vmi_feature_task_switch*) feature;

	if(ts->enable) {
		if(hash_empty(vcpu->arch.vmi_dtb_ht)){
			vmx_vmi_enable_task_switch_trapping(vcpu);
			vcpu->vmi_feature_enabled[KVM_VMI_FEATURE_TRAP_TASK_SWITCH] = 1;
		}

		kvm_vmi_dtb_add_update_entry(vcpu,ts->dtb,ts->incoming,ts->outgoing);
	}
	else {
		kvm_vmi_dtb_rm_entry(vcpu,ts->dtb);

		if(hash_empty(vcpu->arch.vmi_dtb_ht)){
			vmx_vmi_disable_task_switch_trapping(vcpu);
			vcpu->vmi_feature_enabled[KVM_VMI_FEATURE_TRAP_TASK_SWITCH] = 0;
		}

	}

	return 0;
}

int vmx_vmi_feature_control_lbr(struct kvm_vcpu *vcpu, union kvm_vmi_feature *feature)
{
	int r;
	struct kvm_vmi_feature_lbr *lbr = &feature->lbr;

	if (lbr->enable) {
		r = vmx_vmi_enable_lbr(vcpu);
		if (r)
			return r;
		vmx_vmi_set_lbr_select(vcpu, lbr->lbr_select);
		vcpu->vmi_feature_enabled[KVM_VMI_FEATURE_LBR] = 1;
	}
	else {
		vcpu->vmi_feature_enabled[KVM_VMI_FEATURE_LBR] = 0;
		vmx_vmi_disable_lbr(vcpu);
	}

	return 0;
}

int vmx_vmi_feature_control_mtf(struct kvm_vcpu *vcpu, union kvm_vmi_feature *feature)
{
	struct kvm_vmi_feature_mtf *mtf = (struct kvm_vmi_feature_mtf*)feature;
	u32 exec_ctls;
	exec_ctls = vmx_vmi_get_execution_controls();

	if(mtf->enable){
		exec_ctls |= CPU_BASED_MONITOR_TRAP_FLAG;
	}
	else{
		exec_ctls &= ~CPU_BASED_MONITOR_TRAP_FLAG;
	}

	vmx_vmi_update_execution_controls(exec_ctls);
	return 0;
}

static int vmx_vmi_feature_control_slp(struct kvm_vcpu *vcpu,
                                       struct kvm_vmi_feature_slp *feature) {
	u64 gfn;
	bool new_entry;
	struct kvm_vmi_slp_node *i;
	struct hlist_node *tmp;

	if (!(feature->violation |
	        (KVM_VMI_SLP_R | KVM_VMI_SLP_W | KVM_VMI_SLP_X))){
		return -EFAULT;
	}

	if (feature->enable){
		if (feature->global_req){
			if (feature->violation | KVM_VMI_SLP_R) {
				vcpu->arch.vmi_slp_global[KVM_VMI_SLP_R_INDEX]++;
			}
			if (feature->violation | KVM_VMI_SLP_W) {
				vcpu->arch.vmi_slp_global[KVM_VMI_SLP_W_INDEX]++;
			}
			if (feature->violation | KVM_VMI_SLP_X) {
				vcpu->arch.vmi_slp_global[KVM_VMI_SLP_X_INDEX]++;
			}
			if (!vcpu->vmi_feature_enabled[KVM_VMI_FEATURE_SLP]) {
				vcpu->vmi_feature_enabled[KVM_VMI_FEATURE_SLP] = 1;
				kvm_mmu_zap_all(vcpu->kvm);
			}
			return 0;
		}

		for (gfn = feature->gfn; gfn < (feature->gfn + feature->num_pages); gfn++) {
			new_entry = true;
			hash_for_each_possible(vcpu->arch.vmi_slp_ht, i, h, gfn) {
				if (i->gfn == gfn) {
					i->count++;
					new_entry = false;
					break;
				}
			}
			if (new_entry) {
				i = kzalloc(sizeof(struct kvm_vmi_slp_node), GFP_KERNEL);
				i->count = 1;
				i->gfn = gfn;
				hash_add(vcpu->arch.vmi_slp_ht, &(i->h), gfn);
			}
			if (!vcpu->vmi_feature_enabled[KVM_VMI_FEATURE_SLP]) {
				vcpu->vmi_feature_enabled[KVM_VMI_FEATURE_SLP] = 1;
				kvm_mmu_zap_all(vcpu->kvm);
			}
		}
	}
	else {
		if (feature->global_req){
			if ((feature->violation | KVM_VMI_SLP_R) &&
			        (vcpu->arch.vmi_slp_global[KVM_VMI_SLP_R_INDEX] > 0)) {
				vcpu->arch.vmi_slp_global[KVM_VMI_SLP_R_INDEX]--;
			}
			if ((feature->violation | KVM_VMI_SLP_W) &&
			        (vcpu->arch.vmi_slp_global[KVM_VMI_SLP_W_INDEX] > 0)) {
				vcpu->arch.vmi_slp_global[KVM_VMI_SLP_W_INDEX]--;
			}
			if ((feature->violation | KVM_VMI_SLP_X) &&
			        (vcpu->arch.vmi_slp_global[KVM_VMI_SLP_X_INDEX] > 0)){
				vcpu->arch.vmi_slp_global[KVM_VMI_SLP_X_INDEX]--;
			}
		}
		else {
			for (gfn = feature->gfn; gfn < (feature->gfn + feature->num_pages); gfn++) {
				hash_for_each_possible_safe(vcpu->arch.vmi_slp_ht, i, tmp, h, gfn) {
					if (i->gfn == gfn) {
						if (i->count > 0)
							i->count--;
						if (i->count == 0) {
							hash_del(&(i->h));
							kfree(i);
						}
						break;
					}
				}
			}
		}
		if (vcpu->arch.vmi_slp_global[KVM_VMI_SLP_R_INDEX] == 0 &&
		        vcpu->arch.vmi_slp_global[KVM_VMI_SLP_W_INDEX] == 0 &&
				vcpu->arch.vmi_slp_global[KVM_VMI_SLP_X_INDEX] == 0 &&
				hash_empty(vcpu->arch.vmi_slp_ht)) {
			vcpu->vmi_feature_enabled[KVM_VMI_FEATURE_SLP] = 0;
		}
	}

	return 0;
}

int vmx_vmi_feature_control(struct kvm_vcpu *vcpu, union kvm_vmi_feature *feature)
{
	int rv = 0;

	switch (feature->feature) {
	case KVM_VMI_FEATURE_TRAP_TASK_SWITCH:
		rv = vmx_vmi_feature_control_task_switch(vcpu, feature);
		break;
	case KVM_VMI_FEATURE_LBR:
		rv = vmx_vmi_feature_control_lbr(vcpu, feature);
		break;
	case KVM_VMI_FEATURE_MTF:
		rv = vmx_vmi_feature_control_mtf(vcpu,feature);
		break;
	case KVM_VMI_FEATURE_SLP:
		rv = vmx_vmi_feature_control_slp(vcpu,
		                        (struct kvm_vmi_feature_slp*)feature);
		break;
	default:
		kvm_vmi_warning("unknown feature id %d", feature->feature);
		break;
	}

	return rv;
}

int vmx_vmi_slp_update(struct kvm_vcpu *vcpu,
                       struct kvm_vmi_slp_perm *slp_perm) {
	int rv = 0;
	u64 gfn;

	for (gfn = slp_perm->gfn; gfn < (slp_perm->gfn + slp_perm->num_pages); gfn++) {
		rv = mmu_update_spte_permissions(vcpu, gfn << PAGE_SHIFT,
		                                 slp_perm->perm);
		if (rv < 0)
			break;
	}
	return 0;
}
