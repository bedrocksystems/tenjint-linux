/*
 * KVM VMI support
 *
 * Copyright (C) 2019 Bedrock Systems, Inc. All Rights Reserved.
 *
 * Authors:
 *  Jonas Pfoh      <jonas@bedrocksystems.com>
 *  Sebastian Vogl  <sebastian@bedrocksystems.com>
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

#include <linux/hashtable.h>
#include <linux/kvm_host.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_vmi.h>
#include <asm/vmi.h>
#include <kvm/arm_mmu.h>

struct kvm_vmi_slp_node {
	struct hlist_node h;
	u32 count;
	u64 gfn;
};

void kvm_vmi_vcpu_init(struct kvm_vcpu *vcpu) {

}
void kvm_vmi_vcpu_uninit(struct kvm_vcpu *vcpu) {
	int i;
	struct hlist_node *tmp;
	struct kvm_vmi_slp_node *slp_node;

	hash_for_each_safe(vcpu->arch.vmi_slp_ht, i, tmp, slp_node, h) {
		hash_del(&(slp_node->h));
		kfree(slp_node);
	}
}

bool kvm_arm64_task_switch_need_stop(struct kvm_vcpu *vcpu, u8 reg,
                                     u64 in_value, u64 out_value) {
	if (reg < 3 && vcpu->arch.vmi_ts_count[reg])
		return true;
	return false;
}

bool kvm_arm64_slp_need_stop(struct kvm_vcpu *vcpu, u64 gpa, bool read_fault,
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

static int kvm_arm64_feature_control_task_switch(struct kvm_vcpu *vcpu,
                                struct kvm_vmi_feature_task_switch *feature) {
	int i;
	bool disable;

	if (feature->reg > 2)
		return -EFAULT;

	if (feature->enable) {
		vcpu->arch.vmi_ts_count[feature->reg]++;
		vcpu->vmi_feature_enabled[KVM_VMI_FEATURE_TRAP_TASK_SWITCH] = 1;
		*vcpu_hcr(vcpu) |= HCR_TVM;
	}
	else {
		if (vcpu->arch.vmi_ts_count[feature->reg] > 0){
			vcpu->arch.vmi_ts_count[feature->reg]--;
		}
		disable = true;
		for (i=0; i<3; i++){
			if (vcpu->arch.vmi_ts_count[i])
				disable = false;
		}
		if (disable) {
			vcpu->vmi_feature_enabled[KVM_VMI_FEATURE_TRAP_TASK_SWITCH] = 0;
		}
	}
	return 0;
}

static int kvm_arm64_feature_control_slp(struct kvm_vcpu *vcpu,
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
				stage2_unmap_vm(vcpu->kvm);
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
				stage2_unmap_vm(vcpu->kvm);
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

int kvm_arch_vmi_feature_update(struct kvm_vcpu *vcpu,
                                union kvm_vmi_feature *feature) {
	int rv = 0;

	switch (feature->feature) {
	case KVM_VMI_FEATURE_TRAP_TASK_SWITCH:
		rv = kvm_arm64_feature_control_task_switch(vcpu,
		                        (struct kvm_vmi_feature_task_switch*)feature);
		break;
	case KVM_VMI_FEATURE_SLP:
		rv = kvm_arm64_feature_control_slp(vcpu,
		                        (struct kvm_vmi_feature_slp*)feature);
		break;
	default:
		kvm_vmi_warning("unknown feature id %d", feature->feature);
		rv = -ENODEV;
		break;
	}

	return rv;
}

int kvm_arch_vmi_slp_update(struct kvm_vcpu *vcpu,
                            struct kvm_vmi_slp_perm *slp_perm) {
	int rv = 0;
	u64 gfn;

	for (gfn=slp_perm->gfn; gfn < (slp_perm->gfn + slp_perm->num_pages); gfn++) {
		rv = mmu_update_spte_permissions(vcpu, gfn << PAGE_SHIFT,
		                                 slp_perm->perm);
		if (rv < 0)
			break;
	}
	return rv;
}
