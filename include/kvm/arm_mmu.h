/*
 * KVM VMI support
 *
 * Copyright (C) 2020 Bedrock Systems, Inc.
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

#ifndef __KVM_ARM_MMU_H
#define __KVM_ARM_MMU_H

#include <linux/kvm_host.h>

int mmu_update_spte_permissions(struct kvm_vcpu *vcpu, u64 gpa,
                                u64 pte_access);
#endif // __KVM_ARM_MMU_H
