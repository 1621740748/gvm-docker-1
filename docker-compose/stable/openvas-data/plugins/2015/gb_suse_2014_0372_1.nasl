# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850976");
  script_version("2020-01-31T07:58:03+0000");
  script_tag(name:"last_modification", value:"2020-01-31 07:58:03 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2015-10-16 15:25:33 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2013-2212", "CVE-2013-4553", "CVE-2013-4554", "CVE-2013-6885", "CVE-2014-1666", "CVE-2014-1891", "CVE-2014-1892", "CVE-2014-1893", "CVE-2014-1894", "CVE-2014-1950");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SUSE: Security Advisory for Xen (SUSE-SU-2014:0372-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Xen'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise Server 11 Service Pack 2 LTSS Xen
  hypervisor and  toolset has been updated to fix various
  security issues and several bugs.

  The following security issues have been addressed:

  *

  XSA-88: CVE-2014-1950: Use-after-free vulnerability
  in the xc_cpupool_getinfo function in Xen 4.1.x through
  4.3.x, when using a multithreaded toolstack, does not
  properly handle a failure by the xc_cpumap_alloc function,
  which allows local users with access to management
  functions to cause a denial of service (heap corruption)
  and possibly gain privileges via unspecified vectors.
  (bnc#861256)

  *

  XSA-87: CVE-2014-1666: The do_physdev_op function in
  Xen 4.1.5, 4.1.6.1, 4.2.2 through 4.2.3, and 4.3.x does not
  properly restrict access to the (1) PHYSDEVOP_prepare_msix
  and (2) PHYSDEVOP_release_msix operations, which allows
  local PV guests to cause a denial of service (host or guest
  malfunction) or possibly gain privileges via unspecified
  vectors. (bnc#860302)

  *

  XSA-84: CVE-2014-1894: Xen 3.2 (and presumably
  earlier) exhibit both problems with the overflow issue
  being present for more than just the suboperations listed
  above. (bnc#860163)

  *

  XSA-84: CVE-2014-1892 CVE-2014-1893: Xen 3.3 through
  4.1, while not affected by the above overflow, have a
  different overflow issue on FLASK_{GET, SET}BOOL and expose
  unreasonably large memory allocation to aribitrary guests.
  (bnc#860163)

  *

  XSA-84: CVE-2014-1891: The FLASK_{GET, SET}BOOL,
  FLASK_USER and FLASK_CONTEXT_TO_SID suboperations of the
  flask hypercall are vulnerable to an integer overflow on
  the input size. The hypercalls attempt to allocate a buffer
  which is 1 larger than this size and is therefore
  vulnerable to integer overflow and an attempt to allocate
  then access a zero byte buffer. (bnc#860163)

  *

  XSA-82: CVE-2013-6885: The microcode on AMD 16h 00h
  through 0Fh processors does not properly handle the
  interaction between locked instructions and write-combined
  memory types, which allows local users to cause a denial of
  service (system hang) via a crafted application, aka the
  errata 793 issue. (bnc#853049)

  *

  XSA-76: CVE-2013-4554: Xen 3.0.3 through 4.1.x
  (possibly 4.1.6.1), 4.2.x (possibly 4.2.3), and 4.3.x
  (possibly 4.3.1) does not properly prevent access to
  hypercalls, which allows local guest users to gain
  privileges via a crafted application running in ring 1 or
  2. (bnc#849668)

  *

  XSA-74: CVE-2013-4553: The XEN_DOMCTL_getmemlist
  hypercall in Xen 3.4.x through 4.3.x (possibly 4.3.1) does
  not always ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"Xen on SUSE Linux Enterprise Server 11 SP2 LTSS");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"SUSE-SU", value:"2014:0372-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLES11\.0SP2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES11.0SP2") {
  if(!isnull(res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~4.1.6_06~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.1.6_06_3.0.101_0.7.17~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-trace", rpm:"xen-kmp-trace~4.1.6_06_3.0.101_0.7.17~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.1.6_06~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.1.6_06~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.1.6_06~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.1.6_06~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~4.1.6_06~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.1.6_06~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.1.6_06~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.1.6_06_3.0.101_0.7.17~0.5.1", rls:"SLES11.0SP2"))) {
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
