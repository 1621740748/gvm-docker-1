# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1832");
  script_version("2021-08-04T02:01:00+0000");
  script_cve_id("CVE-2019-12435");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-08-04 02:01:00 +0000 (Wed, 04 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-19 15:15:00 +0000 (Wed, 19 Jun 2019)");
  script_tag(name:"creation_date", value:"2020-01-23 12:24:08 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for samba (EulerOS-SA-2019-1832)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1832");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1832");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'samba' package(s) announced via the EulerOS-SA-2019-1832 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Samba 4.9.x before 4.9.9 and 4.10.x before 4.10.5 has a NULL pointer dereference, leading to Denial of Service. This is related to the AD DC DNS management server (dnsserver) RPC server process.(CVE-2019-12435)");

  script_tag(name:"affected", value:"'samba' package(s) on Huawei EulerOS V2.0SP8.");

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

if(release == "EULEROS-2.0SP8") {

  if(!isnull(res = isrpmvuln(pkg:"ctdb", rpm:"ctdb~4.9.1~2.h8.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ctdb-tests", rpm:"ctdb-tests~4.9.1~2.h8.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient", rpm:"libsmbclient~4.9.1~2.h8.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient", rpm:"libwbclient~4.9.1~2.h8.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-samba", rpm:"python2-samba~4.9.1~2.h8.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-samba", rpm:"python3-samba~4.9.1~2.h8.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-samba-test", rpm:"python3-samba-test~4.9.1~2.h8.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba", rpm:"samba~4.9.1~2.h8.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~4.9.1~2.h8.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs", rpm:"samba-client-libs~4.9.1~2.h8.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~4.9.1~2.h8.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-common-libs", rpm:"samba-common-libs~4.9.1~2.h8.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-common-tools", rpm:"samba-common-tools~4.9.1~2.h8.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-dc-libs", rpm:"samba-dc-libs~4.9.1~2.h8.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-krb5-printing", rpm:"samba-krb5-printing~4.9.1~2.h8.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs", rpm:"samba-libs~4.9.1~2.h8.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-pidl", rpm:"samba-pidl~4.9.1~2.h8.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-test", rpm:"samba-test~4.9.1~2.h8.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-test-libs", rpm:"samba-test-libs~4.9.1~2.h8.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~4.9.1~2.h8.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-clients", rpm:"samba-winbind-clients~4.9.1~2.h8.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-krb5-locator", rpm:"samba-winbind-krb5-locator~4.9.1~2.h8.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-modules", rpm:"samba-winbind-modules~4.9.1~2.h8.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
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
