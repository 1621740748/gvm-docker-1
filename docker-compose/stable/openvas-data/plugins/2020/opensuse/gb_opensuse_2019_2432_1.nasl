# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.852909");
  script_version("2020-01-31T08:04:39+0000");
  script_cve_id("CVE-2018-1000876", "CVE-2018-17358", "CVE-2018-17359", "CVE-2018-17360",
                "CVE-2018-17985", "CVE-2018-18309", "CVE-2018-18483", "CVE-2018-18484",
                "CVE-2018-18605", "CVE-2018-18606", "CVE-2018-18607", "CVE-2018-19931",
                "CVE-2018-19932", "CVE-2018-20623", "CVE-2018-20651", "CVE-2018-20671",
                "CVE-2018-6323", "CVE-2018-6543", "CVE-2018-6759", "CVE-2018-6872",
                "CVE-2018-7208", "CVE-2018-7568", "CVE-2018-7569", "CVE-2018-7570",
                "CVE-2018-7642", "CVE-2018-7643", "CVE-2018-8945", "CVE-2019-1010180");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-31 08:04:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-09 09:44:18 +0000 (Thu, 09 Jan 2020)");
  script_name("openSUSE: Security Advisory for binutils (openSUSE-SU-2019:2432-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2019:2432-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-11/msg00008.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'binutils'
  package(s) announced via the openSUSE-SU-2019:2432-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for binutils fixes the following issues:

  binutils was updated to current 2.32 branch [jsc#ECO-368].

  Includes following security fixes:

  - CVE-2018-17358: Fixed invalid memory access in
  _bfd_stab_section_find_nearest_line in syms.c (bsc#1109412)

  - CVE-2018-17359: Fixed invalid memory access exists in bfd_zalloc in
  opncls.c (bsc#1109413)

  - CVE-2018-17360: Fixed heap-based buffer over-read in bfd_getl32 in
  libbfd.c (bsc#1109414)

  - CVE-2018-17985: Fixed a stack consumption problem caused by the
  cplus_demangle_type (bsc#1116827)

  - CVE-2018-18309: Fixed an invalid memory address dereference was
  discovered in read_reloc in reloc.c (bsc#1111996)

  - CVE-2018-18483: Fixed get_count function provided by libiberty that
  allowed attackers to cause a denial of service or other unspecified
  impact (bsc#1112535)

  - CVE-2018-18484: Fixed stack exhaustion in the C++ demangling functions
  provided by libiberty, caused by recursive stack frames (bsc#1112534)

  - CVE-2018-18605: Fixed a heap-based buffer over-read issue was discovered
  in the function sec_merge_hash_lookup causing a denial of service
  (bsc#1113255)

  - CVE-2018-18606: Fixed a NULL pointer dereference in
  _bfd_add_merge_section when attempting to merge sections with large
  alignments, causing denial of service (bsc#1113252)

  - CVE-2018-18607: Fixed a NULL pointer dereference in elf_link_input_bfd
  when used for finding STT_TLS symbols without any TLS section, causing
  denial of service (bsc#1113247)

  - CVE-2018-19931: Fixed a heap-based buffer overflow in
  bfd_elf32_swap_phdr_in in elfcode.h (bsc#1118831)

  - CVE-2018-19932: Fixed an integer overflow and infinite loop caused by
  the IS_CONTAINED_BY_LMA (bsc#1118830)

  - CVE-2018-20623: Fixed a use-after-free in the error function in
  elfcomm.c (bsc#1121035)

  - CVE-2018-20651: Fixed a denial of service via a NULL pointer dereference
  in elf_link_add_object_symbols in elflink.c (bsc#1121034)

  - CVE-2018-20671: Fixed an integer overflow that can trigger a heap-based
  buffer overflow in  load_specific_debug_section in objdump.c
  (bsc#1121056)

  - CVE-2018-1000876: Fixed integer overflow in
  bfd_get_dynamic_reloc_upper_bound, bfd_canonicalize_dynamic_reloc in
  objdump (bsc#1120640)

  - CVE-2019-1010180: Fixed an out of bound memory access that could lead to
  crashes (bsc#1142772)

  - enable xtensa architecture (Tensilica lc6 and related)

  - Use -ffat-lto-objects in order to provide assembly for static libs
  (bsc#1141913).

  - Fixed some LTO build issues (bsc#1133131 bsc#1133232).

  - riscv: Don't check ABI flags if no code section
  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'binutils' package(s) on openSUSE Leap 15.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debuginfo", rpm:"binutils-debuginfo~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-debugsource", rpm:"binutils-debugsource~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel", rpm:"binutils-devel~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-gold", rpm:"binutils-gold~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-gold-debuginfo", rpm:"binutils-gold-debuginfo~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-devel-32bit", rpm:"binutils-devel-32bit~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-aarch64-binutils", rpm:"cross-aarch64-binutils~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-aarch64-binutils-debuginfo", rpm:"cross-aarch64-binutils-debuginfo~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-aarch64-binutils-debugsource", rpm:"cross-aarch64-binutils-debugsource~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-arm-binutils", rpm:"cross-arm-binutils~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-arm-binutils-debuginfo", rpm:"cross-arm-binutils-debuginfo~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-arm-binutils-debugsource", rpm:"cross-arm-binutils-debugsource~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-avr-binutils", rpm:"cross-avr-binutils~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-avr-binutils-debuginfo", rpm:"cross-avr-binutils-debuginfo~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-avr-binutils-debugsource", rpm:"cross-avr-binutils-debugsource~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-epiphany-binutils", rpm:"cross-epiphany-binutils~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-epiphany-binutils-debuginfo", rpm:"cross-epiphany-binutils-debuginfo~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-epiphany-binutils-debugsource", rpm:"cross-epiphany-binutils-debugsource~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-hppa-binutils", rpm:"cross-hppa-binutils~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-hppa-binutils-debuginfo", rpm:"cross-hppa-binutils-debuginfo~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-hppa-binutils-debugsource", rpm:"cross-hppa-binutils-debugsource~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-hppa64-binutils", rpm:"cross-hppa64-binutils~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-hppa64-binutils-debuginfo", rpm:"cross-hppa64-binutils-debuginfo~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-hppa64-binutils-debugsource", rpm:"cross-hppa64-binutils-debugsource~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-i386-binutils", rpm:"cross-i386-binutils~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-i386-binutils-debuginfo", rpm:"cross-i386-binutils-debuginfo~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-i386-binutils-debugsource", rpm:"cross-i386-binutils-debugsource~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ia64-binutils", rpm:"cross-ia64-binutils~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ia64-binutils-debuginfo", rpm:"cross-ia64-binutils-debuginfo~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ia64-binutils-debugsource", rpm:"cross-ia64-binutils-debugsource~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-m68k-binutils", rpm:"cross-m68k-binutils~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-m68k-binutils-debuginfo", rpm:"cross-m68k-binutils-debuginfo~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-m68k-binutils-debugsource", rpm:"cross-m68k-binutils-debugsource~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-mips-binutils", rpm:"cross-mips-binutils~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-mips-binutils-debuginfo", rpm:"cross-mips-binutils-debuginfo~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-mips-binutils-debugsource", rpm:"cross-mips-binutils-debugsource~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc-binutils", rpm:"cross-ppc-binutils~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc-binutils-debuginfo", rpm:"cross-ppc-binutils-debuginfo~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc-binutils-debugsource", rpm:"cross-ppc-binutils-debugsource~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc64-binutils", rpm:"cross-ppc64-binutils~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc64-binutils-debuginfo", rpm:"cross-ppc64-binutils-debuginfo~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc64-binutils-debugsource", rpm:"cross-ppc64-binutils-debugsource~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc64le-binutils", rpm:"cross-ppc64le-binutils~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc64le-binutils-debuginfo", rpm:"cross-ppc64le-binutils-debuginfo~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-ppc64le-binutils-debugsource", rpm:"cross-ppc64le-binutils-debugsource~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-riscv64-binutils", rpm:"cross-riscv64-binutils~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-riscv64-binutils-debuginfo", rpm:"cross-riscv64-binutils-debuginfo~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-riscv64-binutils-debugsource", rpm:"cross-riscv64-binutils-debugsource~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-rx-binutils", rpm:"cross-rx-binutils~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-rx-binutils-debuginfo", rpm:"cross-rx-binutils-debuginfo~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-rx-binutils-debugsource", rpm:"cross-rx-binutils-debugsource~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-s390-binutils", rpm:"cross-s390-binutils~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-s390-binutils-debuginfo", rpm:"cross-s390-binutils-debuginfo~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-s390-binutils-debugsource", rpm:"cross-s390-binutils-debugsource~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-s390x-binutils", rpm:"cross-s390x-binutils~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-s390x-binutils-debuginfo", rpm:"cross-s390x-binutils-debuginfo~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-s390x-binutils-debugsource", rpm:"cross-s390x-binutils-debugsource~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-sparc-binutils", rpm:"cross-sparc-binutils~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-sparc-binutils-debuginfo", rpm:"cross-sparc-binutils-debuginfo~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-sparc-binutils-debugsource", rpm:"cross-sparc-binutils-debugsource~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-sparc64-binutils", rpm:"cross-sparc64-binutils~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-sparc64-binutils-debuginfo", rpm:"cross-sparc64-binutils-debuginfo~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-sparc64-binutils-debugsource", rpm:"cross-sparc64-binutils-debugsource~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-spu-binutils", rpm:"cross-spu-binutils~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-spu-binutils-debuginfo", rpm:"cross-spu-binutils-debuginfo~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-spu-binutils-debugsource", rpm:"cross-spu-binutils-debugsource~2.32~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
