# Copyright (C) 2015 Eero Volotinen
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of their respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.122717");
  script_version("2020-03-13T10:06:41+0000");
  script_tag(name:"creation_date", value:"2015-10-22 08:30:58 +0300 (Thu, 22 Oct 2015)");
  script_tag(name:"last_modification", value:"2020-03-13 10:06:41 +0000 (Fri, 13 Mar 2020)");
  script_name("Oracle Linux Local Check: ELSA-2015-1919");
  script_tag(name:"insight", value:"ELSA-2015-1919 - java-1.8.0-openjdk security update. Please see the references for more insight.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Oracle Linux Local Security Checks ELSA-2015-1919");
  script_xref(name:"URL", value:"http://linux.oracle.com/errata/ELSA-2015-1919.html");
  script_cve_id("CVE-2015-4734", "CVE-2015-4803", "CVE-2015-4805", "CVE-2015-4806", "CVE-2015-4835", "CVE-2015-4840", "CVE-2015-4842", "CVE-2015-4843", "CVE-2015-4844", "CVE-2015-4860", "CVE-2015-4868", "CVE-2015-4872", "CVE-2015-4881", "CVE-2015-4882", "CVE-2015-4883", "CVE-2015-4893", "CVE-2015-4903", "CVE-2015-4911");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux(7|6)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Eero Volotinen");
  script_family("Oracle Linux Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "OracleLinux7")
{
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk", rpm:"java-1.8.0-openjdk~1.8.0.65~2.b17.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-accessibility", rpm:"java-1.8.0-openjdk-accessibility~1.8.0.65~2.b17.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo", rpm:"java-1.8.0-openjdk-demo~1.8.0.65~2.b17.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel", rpm:"java-1.8.0-openjdk-devel~1.8.0.65~2.b17.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless", rpm:"java-1.8.0-openjdk-headless~1.8.0.65~2.b17.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc", rpm:"java-1.8.0-openjdk-javadoc~1.8.0.65~2.b17.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-src", rpm:"java-1.8.0-openjdk-src~1.8.0.65~2.b17.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }

}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk", rpm:"java-1.8.0-openjdk~1.8.0.65~0.b17.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-debug", rpm:"java-1.8.0-openjdk-debug~1.8.0.65~0.b17.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo", rpm:"java-1.8.0-openjdk-demo~1.8.0.65~0.b17.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo-debug", rpm:"java-1.8.0-openjdk-demo-debug~1.8.0.65~0.b17.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel", rpm:"java-1.8.0-openjdk-devel~1.8.0.65~0.b17.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel-debug", rpm:"java-1.8.0-openjdk-devel-debug~1.8.0.65~0.b17.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless", rpm:"java-1.8.0-openjdk-headless~1.8.0.65~0.b17.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless-debug", rpm:"java-1.8.0-openjdk-headless-debug~1.8.0.65~0.b17.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc", rpm:"java-1.8.0-openjdk-javadoc~1.8.0.65~0.b17.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc-debug", rpm:"java-1.8.0-openjdk-javadoc-debug~1.8.0.65~0.b17.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-src", rpm:"java-1.8.0-openjdk-src~1.8.0.65~0.b17.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-src-debug", rpm:"java-1.8.0-openjdk-src-debug~1.8.0.65~0.b17.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }

}
if (__pkg_match) exit(99);
  exit(0);

