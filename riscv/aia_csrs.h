// See LICENSE for license details.
#pragma once
#include "csrs.h"
#include "imsic.h"

class topi_csr_t: public csr_t {
 public:
  topi_csr_t(processor_t* const proc, const reg_t addr, csr_t_p ip, csr_t_p ie, bool vs, csr_t_p ideleg = nullptr, csr_t_p vien = nullptr, csr_t_p hip = nullptr, csr_t_p hie = nullptr);

  virtual void verify_permissions(insn_t insn, bool write) const override;
  virtual reg_t read() const noexcept override;
  void set_int_pri_order(const std::vector<reg_t> &v);
 protected:
  virtual bool unlogged_write(const reg_t val) noexcept override;
 private:
  csr_t_p ip;
  csr_t_p ie;
  bool vs;
  csr_t_p ideleg;
  csr_t_p vien;
  csr_t_p hip;
  csr_t_p hie;
  // interrupts from highest to lowest priorities (6.1)
  #define DEFAULT_INT_PRI {47, 23, 46, 45, 22, 44, 43, 21, 42, 41, 20, 40, 11, 3, 7, 9, 1, 5, 12, 10, 2, 6, 13, 39, 19, 38, 37, 18, 36, 35, 17, 34, 33, 16, 32};
  std::vector<reg_t> int_pri_order;
};

class topei_csr_t: public csr_t {
 public:
  topei_csr_t(processor_t* const proc, const reg_t addr, imsic_file_t_p const imsic);

  virtual reg_t read() const noexcept override;
  virtual void verify_permissions(insn_t insn, bool write) const override;
 protected:
  virtual bool unlogged_write(const reg_t val) noexcept override;
 private:
  imsic_file_t_p get_imsic() const noexcept;
  imsic_file_t_p const imsic;
  bool vs;
};

class aia_ireg_proxy_csr_t: public csr_t {
 public:
  aia_ireg_proxy_csr_t(processor_t* const proc, const reg_t addr, csr_t_p iselect);
  virtual reg_t read() const noexcept override;
  virtual void verify_permissions(insn_t insn, bool write) const override;
  csrmap_t_p get_csrmap(reg_t vgein = 0);
 protected:
  virtual bool unlogged_write(const reg_t val) noexcept override;
 private:
  csr_t_p get_reg() const noexcept;
  csr_t_p iselect;
  bool vs;
  csrmap_t_p csrmap;
};
typedef std::shared_ptr<aia_ireg_proxy_csr_t> aia_ireg_proxy_csr_t_p;

class hgeip_csr_t final: public csr_t {
 public:
  hgeip_csr_t(processor_t* const proc, const reg_t addr);
  virtual reg_t read() const noexcept override;
 protected:
  virtual bool unlogged_write(const reg_t val) noexcept override;
};

class hgeie_csr_t final: public masked_csr_t {
 public:
  hgeie_csr_t(processor_t* const proc, const reg_t addr, const reg_t geilen);
 protected:
  virtual bool unlogged_write(const reg_t val) noexcept override;
};

// AIA registers needs permissions checked
// (the original virtualized_csr_t does not call verify_permission of the underlying CSRs)
class virtualized_aia_csr_t: public virtualized_csr_t {
 public:
  virtualized_aia_csr_t(processor_t* const proc, csr_t_p orig, csr_t_p virt);
  virtual void verify_permissions(insn_t insn, bool write) const override;
};

// Filter CSR accesses through xstateen[reg]
class stateen_filter_csr_t: public proxy_csr_t {
 public:
  stateen_filter_csr_t(processor_t* const proc, csr_t_p csr, reg_t mask, reg_t stateen_reg = 0);
  virtual void verify_permissions(insn_t insn, bool write) const override;
 private:
  reg_t mask;
  reg_t stateen_reg;
};

