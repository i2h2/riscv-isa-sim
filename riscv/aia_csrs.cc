// See LICENSE for license details.

#include "csrs.h"
// For processor_t:
#include "processor.h"
// For get_field():
#include "decode.h"
// For trap_virtual_instruction and trap_illegal_instruction:
#include "trap.h"
// For require():
#include "insn_macros.h"
#include "arith.h"
#include "imsic.h"
// std::max
#include <algorithm>

topi_csr_t::topi_csr_t(processor_t* const proc, const reg_t addr, csr_t_p ip, csr_t_p ie, bool vs, csr_t_p ideleg, csr_t_p vien, csr_t_p hip, csr_t_p hie) : csr_t(proc, addr), ip(ip), ie(ie), vs(vs), ideleg(ideleg), vien(vien), hip(hip), hie(hie) {
  int_pri_order = DEFAULT_INT_PRI;
}

void topi_csr_t::set_int_pri_order(const std::vector<reg_t> &v) {
  int_pri_order = v;
}

void topi_csr_t::verify_permissions(insn_t insn, bool write) const {
  // do not check virtualized vstopi as it has a different address when V=1
  if (!vs)
    csr_t::verify_permissions(insn, write);
}

reg_t topi_csr_t::read() const noexcept {
  reg_t vs_candidate = 0;
  // generate a list of default candidates from mip/mie
  // if VS, see vstopi behavior in 7.3.3
  if (vs) {
    reg_t vgein = get_field(state->hstatus->read(), HSTATUS_VGEIN);
    reg_t hvictl = state->hvictl->read();
    reg_t hvictl_iid = get_field(hvictl, HVICTL_IID);
    reg_t hvictl_iprio = get_field(hvictl, HVICTL_IPRIO);
    bool hvictl_ipriom = get_field(hvictl, HVICTL_IPRIOM);
    // check to see if vgein is valid
    if (vgein && !proc->imsic->vgein_valid(vgein))
      vgein = 0;
    if (state->mip->read() & state->mie->read() & MIP_VSEIP) {
      // default for case 3
      reg_t topi_prio = 255;
      if (vgein) {
        // case 1
        topi_prio = get_field(state->vstopei->read(), IMSIC_TOPI_IPRIO);
      } else if (vgein == 0 && hvictl_iid == IRQ_S_EXT && hvictl_iprio) {
        // case 2
        topi_prio = hvictl_iprio;
      }
      reg_t v = 0;
      v = set_field(v, TOPI_IID, IRQ_S_EXT);
      // if IPRIOM use IPRIO, or 1
      v = set_field(v, TOPI_IPRIO, hvictl_ipriom ? std::max<reg_t>(topi_prio, 255) : 1);
      vs_candidate = v;
    }
    // case 4: VTI = 0 is handled by the non-VS case
    // case 5: VTI = 1 and IID != 9
    if (get_field(hvictl, HVICTL_VTI) && hvictl_iid != IRQ_S_EXT) {
      // DPR determines if the priority is higher or lower than VSEIP
      // If no SEIP or DPR=0, overwrite the candidate
      if (!vs_candidate || !get_field(hvictl, HVICTL_DPR)) {
        reg_t v = 0;
        v = set_field(v, TOPI_IID, hvictl_iid);
        v = set_field(v, TOPI_IPRIO, hvictl_ipriom ? hvictl_iprio : 1);
        vs_candidate = v;
      }
    }
  }
  // ideleg only exists in M & HS modes. vstopi would not need to check ideleg
  // if vien exists (M & HS), mask out those interrupts
  reg_t pend = ip->read() & ie->read();
  if (hip && hie)
    pend |= hip->read() & hie->read();
  reg_t ints = pend & (ideleg ? ~ideleg->read() : ~reg_t(0)) & (vien ? ~vien->read() : ~reg_t(0));

  // if no physical interrupt pending, check virtual
  if (!ints)
    return vs_candidate ? vs_candidate : 0;

  reg_t v = 0;
  v = set_field(v, TOPI_IPRIO, 1);
  for (auto &x : int_pri_order) {
    // virt: since all interrupts are of priority 1, use the default order until VSEIP
    // at that point, prioritize virtual candidate over VSEIP
    if (vs_candidate && x == IRQ_S_EXT)
      return vs_candidate;
    if (ints && (ints & (reg_t(1) << x))) {
      v = set_field(v, TOPI_IID, x);
      return v;
    }
  }
  // just in case IRQ_VS_EXT(10) is not in the priority order vector - prioritize over the rest
  if (vs_candidate)
    return vs_candidate;
  // no ordering beyond the default priorities
  v = set_field(v, TOPI_IID, ctz(ints));
  return v;
}

bool topi_csr_t::unlogged_write(const reg_t val) noexcept {
  // *topi is read-only so this method is never used.
  return true;
}

topei_csr_t::topei_csr_t(processor_t* const proc, const reg_t addr, imsic_file_t_p const imsic) : csr_t(proc, addr), imsic(imsic), vs(!imsic) {
}

void topei_csr_t::verify_permissions(insn_t insn, bool write) const {
  // skip verfy_permissions chaining on a VS reg because the address is remapped
  if (!vs)
    csr_t::verify_permissions(insn, write);
  // VGEIN must be 0 or valid
  reg_t vgein = get_field(state->hstatus->read(), HSTATUS_VGEIN);
  if (!imsic && (vgein && !proc->imsic->vgein_valid(vgein))) {
    if (state->v)
      throw trap_virtual_instruction(insn.bits());
    else
      throw trap_illegal_instruction(insn.bits());
  }
}

imsic_file_t_p topei_csr_t::get_imsic() const noexcept {
  // non-virtualized registers have pointers to IMSIC
  if (imsic)
    return imsic;

  // Virtualized IMSIC depends on hstatus.vgein
  reg_t vgein = get_field(state->hstatus->read(), HSTATUS_VGEIN);
  if (!vgein || !proc->imsic->vgein_valid(vgein))
    return nullptr;
  return proc->imsic->vs[vgein];
}

reg_t topei_csr_t::read() const noexcept {
  imsic_file_t_p p = get_imsic();
  if (!p)
    return 0;

  reg_t iid = p->topei();
  reg_t v = 0;
  v = set_field(v, IMSIC_TOPI_IPRIO, iid);
  v = set_field(v, IMSIC_TOPI_IID, iid);
  return v;
}

bool topei_csr_t::unlogged_write(const reg_t val) noexcept {
  imsic_file_t_p p = get_imsic();
  if (!p)
    return false;
  p->claimei(p->topei());
  return true;
}

aia_ireg_proxy_csr_t::aia_ireg_proxy_csr_t(processor_t* const proc, const reg_t addr, csr_t_p iselect) : csr_t(proc, addr), iselect(iselect), vs(false), csrmap(nullptr) {
  auto xlen = proc->get_xlen();
  switch (address) {
    case CSR_MIREG:
    {
      csrmap = &proc->imsic->m->csrmap;
      // IMSIC registers are defined to be 32-bit and odd ones drop out when xlen is 64
      const unsigned num_iprio_regs = (MISELECT_IPRIO_TOP - MISELECT_IPRIO + 1) / 2;
      for (size_t i = 0; i < num_iprio_regs; i++) {
        auto iprio = std::make_shared<const_csr_t>(proc, MISELECT_IPRIO + i * 2, 0);
        if (xlen == 64) {
          (*csrmap)[MISELECT_IPRIO + i * 2] = iprio;
        } else {
          (*csrmap)[MISELECT_IPRIO + i * 2] = std::make_shared<rv32_low_csr_t>(proc, MISELECT_IPRIO + i * 2, iprio);
          (*csrmap)[MISELECT_IPRIO + i * 2 + 1] = std::make_shared<rv32_high_csr_t>(proc, MISELECT_IPRIO + i * 2 + 1, iprio);
        }
      }
      break;
    }
    case CSR_SIREG:
    {
      csrmap = &proc->imsic->s->csrmap;
      // IMSIC registers are defined to be 32-bit and odd ones drop out when xlen is 64
      const unsigned num_iprio_regs = (SISELECT_IPRIO_TOP - SISELECT_IPRIO + 1) / 2;
      for (size_t i = 0; i < num_iprio_regs; i++) {
        auto iprio = std::make_shared<const_csr_t>(proc, SISELECT_IPRIO + i * 2, 0);
        if (xlen == 64) {
          (*csrmap)[SISELECT_IPRIO + i * 2] = iprio;
        } else {
          (*csrmap)[SISELECT_IPRIO + i * 2] = std::make_shared<rv32_low_csr_t>(proc, SISELECT_IPRIO + i * 2, iprio);
          (*csrmap)[SISELECT_IPRIO + i * 2 + 1] = std::make_shared<rv32_high_csr_t>(proc, SISELECT_IPRIO + i * 2 + 1, iprio);
        }
      }
      break;
    }
    case CSR_VSIREG:
      // Virtualized ireg (vsireg) does not have a csrmap ecause it changes based on hstatus.vgein
      vs = true;
      break;
    default:
      // Unexpected *ireg address
      assert(false);
  }
}

csr_t_p aia_ireg_proxy_csr_t::get_reg() const noexcept {
  reg_t reg = iselect->read();
  if (vs) {
    // vsireg - look up by vgein
    reg_t vgein = get_field(state->hstatus->read(), HSTATUS_VGEIN);
    return vgein ? proc->imsic->get_vs_reg(vgein, reg) : nullptr;
  }
  // !vsireg
  return csrmap->count(reg) ? (*csrmap)[reg] : nullptr;
}

reg_t aia_ireg_proxy_csr_t::read() const noexcept {
  csr_t_p reg = get_reg();
  return reg ? reg->read() : 0;
}

void aia_ireg_proxy_csr_t::verify_permissions(insn_t insn, bool write) const {
  // skip verfy_permissions chaining on a VS reg because the address is remapped
  if (!vs)
    csr_t::verify_permissions(insn, write);
  if (get_reg() == nullptr) {
    if (state->v)
      throw trap_virtual_instruction(insn.bits());
    else
      throw trap_illegal_instruction(insn.bits());
  }
  if (proc->extension_enabled(EXT_SMSTATEEN)) {
    // if iselect >= IMSIC and xSTATEEN_IMSIC not set
    reg_t isel = iselect->read();
    if (!state->v && state->prv < PRV_M && isel >= SISELECT_IMSIC && isel <= SISELECT_IMSIC_TOP && !(state->mstateen[0]->read() & MSTATEEN0_IMSIC))
      throw trap_illegal_instruction(insn.bits());
    if (state->v && isel >= VSISELECT_IMSIC && isel <= VSISELECT_IMSIC_TOP && !(state->hstateen[0]->read() & HSTATEEN0_IMSIC))
      throw trap_virtual_instruction(insn.bits());
  }
  // if VS & invalid VGEIN
  if (vs && !get_reg()) {
    if (state->v)
      throw trap_virtual_instruction(insn.bits());
    else
      throw trap_illegal_instruction(insn.bits());
  }
}

bool aia_ireg_proxy_csr_t::unlogged_write(const reg_t val) noexcept {
  csr_t_p reg = get_reg();
  if (!reg)
    return false;
  reg->write(val);
  return true;
}

csrmap_t_p aia_ireg_proxy_csr_t::get_csrmap(reg_t vgein) {
  if (!vs)
    return csrmap;
  return proc->imsic->get_vs_csrmap(vgein ? vgein : get_field(state->hstatus->read(), HSTATUS_VGEIN));
}

hgeip_csr_t::hgeip_csr_t(processor_t* const proc, const reg_t addr) : csr_t(proc, addr) {
}

reg_t hgeip_csr_t::read() const noexcept {
  // scan through all VGEINs
  reg_t v = 0;
  for (auto &i: proc->imsic->vs) {
    if (i.second->topei())
      v |= reg_t(1) << i.first;
  }
  return v;
}

bool hgeip_csr_t::unlogged_write(const reg_t val) noexcept {
  // read-only register
  return false;
}

hgeie_csr_t::hgeie_csr_t(processor_t* const proc, const reg_t addr, const reg_t geilen) : masked_csr_t(proc, addr, ((reg_t(1) << geilen) - 1) << 1, 0) {
}

bool hgeie_csr_t::unlogged_write(const reg_t val) noexcept {
  bool sgeip = val & proc->get_state()->hgeip->read();
  // update mip.SGEIP if the hypervisor traps guest SEIP to itself
  state->mip->backdoor_write_with_mask(MIP_SGEIP, sgeip ? MIP_SGEIP : 0);
  return masked_csr_t::unlogged_write(val);
}

virtualized_aia_csr_t::virtualized_aia_csr_t(processor_t* const proc, csr_t_p orig, csr_t_p virt):
  virtualized_csr_t(proc, orig, virt) {
}

void virtualized_aia_csr_t::verify_permissions(insn_t insn, bool write) const {
  csr_t::verify_permissions(insn, write);
  if (state->v)
    virt_csr->verify_permissions(insn, write);
  else
    orig_csr->verify_permissions(insn, write);
}

stateen_filter_csr_t::stateen_filter_csr_t(processor_t* const proc, csr_t_p csr, reg_t mask, reg_t stateen_reg):
  proxy_csr_t(proc, csr->address, csr),
  mask(mask),
  stateen_reg(stateen_reg) {
}

void stateen_filter_csr_t::verify_permissions(insn_t insn, bool write) const {
  // the protected CSR may be overriding verify_permission
  delegate->verify_permissions(insn, write);
  if (state->v && !(state->hstateen[stateen_reg]->read() & mask))
    throw trap_virtual_instruction(insn.bits());
  if (!state->v && !(state->mstateen[stateen_reg]->read() & mask))
    throw trap_illegal_instruction(insn.bits());
}
