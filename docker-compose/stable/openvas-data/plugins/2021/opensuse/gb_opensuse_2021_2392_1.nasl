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
  script_oid("1.3.6.1.4.1.25623.1.0.853997");
  script_version("2021-08-03T07:24:09+0000");
  script_cve_id("CVE-2021-34558");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-08-03 07:24:09 +0000 (Tue, 03 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-07-20 03:02:34 +0000 (Tue, 20 Jul 2021)");
  script_name("openSUSE: Security Advisory for go1.16 (openSUSE-SU-2021:2392-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:2392-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/AKQH4LHYIFOWBEGMGHD7S7TTV7JL4U7W");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.16'
  package(s) announced via the openSUSE-SU-2021:2392-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.16 fixes the following issues:

     go1.16.6 (released 2021-07-12, bsc#1182345) includes a security fix to the
     crypto/tls package, as well as bug fixes to the compiler, and the net and
     net/http packages.

     Security issue fixed:

     CVE-2021-34558: Fixed crypto/tls: clients can panic when provided a
     certificate of the wrong type for the negotiated parameters (bsc#1188229)

     go1.16 release:

  * bsc#1188229 go#47143 CVE-2021-34558

  * go#47145 security: fix CVE-2021-34558

  * go#46999 net: LookupMX behaviour broken

  * go#46981 net: TestCVE202133195 fails if /etc/resolv.conf specifies ndots
       larger than 3

  * go#46769 syscall: TestGroupCleanupUserNamespace test failure on Fedora

  * go#46657 runtime: deeply nested struct initialized with non-zero values

  * go#44984 net/http: server not setting Content-Length in certain cases");

  script_tag(name:"affected", value:"'go1.16' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"go1.16", rpm:"go1.16~1.16.6~1.20.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.16-doc", rpm:"go1.16-doc~1.16.6~1.20.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.16-race", rpm:"go1.16-race~1.16.6~1.20.1", rls:"openSUSELeap15.3"))) {
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