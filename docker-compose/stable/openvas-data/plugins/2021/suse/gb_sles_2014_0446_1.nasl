# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2014.0446.1");
  script_cve_id("CVE-2006-1056", "CVE-2007-0998", "CVE-2012-3497", "CVE-2012-4411", "CVE-2012-4535", "CVE-2012-4537", "CVE-2012-4538", "CVE-2012-4539", "CVE-2012-4544", "CVE-2012-5510", "CVE-2012-5511", "CVE-2012-5513", "CVE-2012-5514", "CVE-2012-5515", "CVE-2012-5634", "CVE-2012-6075", "CVE-2012-6333", "CVE-2013-0153", "CVE-2013-0154", "CVE-2013-1432", "CVE-2013-1442", "CVE-2013-1917", "CVE-2013-1918", "CVE-2013-1919", "CVE-2013-1920", "CVE-2013-1952", "CVE-2013-1964", "CVE-2013-2072", "CVE-2013-2076", "CVE-2013-2077", "CVE-2013-2194", "CVE-2013-2195", "CVE-2013-2196", "CVE-2013-2211", "CVE-2013-2212", "CVE-2013-4329", "CVE-2013-4355", "CVE-2013-4361", "CVE-2013-4368", "CVE-2013-4494", "CVE-2013-4553", "CVE-2013-4554", "CVE-2013-6885", "CVE-2014-1891", "CVE-2014-1892", "CVE-2014-1893", "CVE-2014-1894");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:21 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-11 15:21:00 +0000 (Tue, 11 Aug 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2014:0446-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2014:0446-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2014/suse-su-20140446-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Xen' package(s) announced via the SUSE-SU-2014:0446-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise Server 11 Service Pack 1 LTSS Xen hypervisor and toolset have been updated to fix various security issues and some bugs.

The following security issues have been addressed:

 *

 XSA-84: CVE-2014-1894: Xen 3.2 (and presumably earlier) exhibit both problems with the overflow issue being present for more than just the suboperations listed above. (bnc#860163)

 *

 XSA-84: CVE-2014-1892 CVE-2014-1893: Xen 3.3 through 4.1, while not affected by the above overflow, have a different overflow issue on FLASK_{GET,SET}BOOL and expose unreasonably large memory allocation to aribitrary guests.
(bnc#860163)

 *

 XSA-84: CVE-2014-1891: The FLASK_{GET,SET}BOOL,
FLASK_USER and FLASK_CONTEXT_TO_SID suboperations of the flask hypercall are vulnerable to an integer overflow on the input size. The hypercalls attempt to allocate a buffer which is 1 larger than this size and is therefore vulnerable to integer overflow and an attempt to allocate then access a zero byte buffer. (bnc#860163)

 *

 XSA-82: CVE-2013-6885: The microcode on AMD 16h 00h through 0Fh processors does not properly handle the interaction between locked instructions and write-combined memory types, which allows local users to cause a denial of service (system hang) via a crafted application, aka the errata 793 issue. (bnc#853049)

 *

 XSA-76: CVE-2013-4554: Xen 3.0.3 through 4.1.x
(possibly 4.1.6.1), 4.2.x (possibly 4.2.3), and 4.3.x
(possibly 4.3.1) does not properly prevent access to hypercalls, which allows local guest users to gain privileges via a crafted application running in ring 1 or 2. (bnc#849668)

 *

 XSA-74: CVE-2013-4553: The XEN_DOMCTL_getmemlist hypercall in Xen 3.4.x through 4.3.x (possibly 4.3.1) does not always obtain the page_alloc_lock and mm_rwlock in the same order, which allows local guest administrators to cause a denial of service (host deadlock). (bnc#849667)

 *

 XSA-73: CVE-2013-4494: Xen before 4.1.x, 4.2.x, and 4.3.x does not take the page_alloc_lock and grant_table.lock in the same order, which allows local guest administrators with access to multiple vcpus to cause a denial of service (host deadlock) via unspecified vectors. (bnc#848657)

 *

 XSA-67: CVE-2013-4368: The outs instruction emulation in Xen 3.1.x, 4.2.x, 4.3.x, and earlier, when using FS: or GS: segment override, uses an uninitialized variable as a segment base, which allows local 64-bit PV guests to obtain sensitive information (hypervisor stack content) via unspecified vectors related to stale data in a segment register. (bnc#842511)

 *

 XSA-66: CVE-2013-4361: The fbld instruction emulation in Xen 3.3.x through 4.3.x does not use the correct variable for the source effective address, which allows local HVM guests to obtain hypervisor stack information by reading the values used by the instruction. (bnc#841766)

 *

 XSA-63: CVE-2013-4355: Xen 4.3.x and earlier does not properly handle certain ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Xen' package(s) on SUSE Linux Enterprise Server 11 SP1.");

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

if(release == "SLES11.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.0.3_21548_16~0.5.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.0.3_21548_16~0.5.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~4.0.3_21548_16~0.5.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.0.3_21548_16_2.6.32.59_0.9~0.5.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-trace", rpm:"xen-kmp-trace~4.0.3_21548_16_2.6.32.59_0.9~0.5.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.0.3_21548_16~0.5.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.0.3_21548_16~0.5.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.0.3_21548_16~0.5.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.0.3_21548_16_2.6.32.59_0.9~0.5.1", rls:"SLES11.0SP1"))) {
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
