#include <linux/kvm_host.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_vmi.h>
#include <asm/vmi.h>

void kvm_vmi_vcpu_init(struct kvm_vcpu *vcpu) {

}
void kvm_vmi_vcpu_uninit(struct kvm_vcpu *vcpu) {

}

bool kvm_arm64_task_switch_need_stop(struct kvm_vcpu *vcpu, u8 reg,
                                     u64 in_value, u64 out_value) {
	if (reg < 3 && vcpu->arch.vmi_ts_count[reg])
		return true;
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

int kvm_arch_vmi_feature_update(struct kvm_vcpu *vcpu,
                                union kvm_vmi_feature *feature) {
	int rv = 0;

	switch (feature->feature) {
	case KVM_VMI_FEATURE_TRAP_TASK_SWITCH:
		rv = kvm_arm64_feature_control_task_switch(vcpu,
		                        (struct kvm_vmi_feature_task_switch*)feature);
		break;
	default:
		kvm_vmi_warning("unknown feature id %d", feature->feature);
		rv = -ENODEV;
		break;
	}

	return rv;
}
