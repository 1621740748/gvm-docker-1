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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1544");
  script_version("2021-03-05T07:10:16+0000");
  script_cve_id("CVE-2020-28196");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-03-05 07:10:16 +0000 (Fri, 05 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-05 07:10:16 +0000 (Fri, 05 Mar 2021)");
  script_name("Huawei EulerOS: Security Advisory for krb5 (EulerOS-SA-2021-1544)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64-3\.0\.6\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1544");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1544");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'krb5' package(s) announced via the EulerOS-SA-2021-1544 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"MIT Kerberos 5 (aka krb5) before 1.17.2 and 1.18.x before 1.18.3 allows unbounded recursion via an ASN.1-encoded Kerberos message because the lib/krb5/asn.1/asn1_encode.c support for BER indefinite lengths lacks a recursion limit.(CVE-2020-28196)");

  script_tag(name:"affected", value:"'krb5' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.6.0.");

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

if(release == "EULEROSVIRTARM64-3.0.6.0") {

  if(!isnull(res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.16.1~21.h5.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-libs", rpm:"krb5-libs~1.16.1~21.h5.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-pkinit", rpm:"krb5-pkinit~1.16.1~21.h5.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.16.1~21.h5.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.16.1~21.h5.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
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