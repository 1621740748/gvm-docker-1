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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2372");
  script_version("2021-08-04T11:01:00+0000");
  script_cve_id("CVE-2017-14461", "CVE-2017-15130", "CVE-2019-11500");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-08-04 11:01:00 +0000 (Wed, 04 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-06 15:15:00 +0000 (Fri, 06 Sep 2019)");
  script_tag(name:"creation_date", value:"2020-01-23 12:51:44 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for dovecot (EulerOS-SA-2019-2372)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2372");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2372");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'dovecot' package(s) announced via the EulerOS-SA-2019-2372 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A denial of service flaw was found in dovecot before 2.2.34. An attacker able to generate random SNI server names could exploit TLS SNI configuration lookups, leading to excessive memory usage and the process to restart.(CVE-2017-15130)

A specially crafted email delivered over SMTP and passed on to Dovecot by MTA can trigger an out of bounds read resulting in potential sensitive information disclosure and denial of service. In order to trigger this vulnerability, an attacker needs to send a specially crafted email message to the server.(CVE-2017-14461)

In Dovecot before 2.2.36.4 and 2.3.x before 2.3.7.2 (and Pigeonhole before 0.5.7.2), protocol processing can fail for quoted strings. This occurs because '\0' characters are mishandled, and can lead to out-of-bounds writes and remote code execution.(CVE-2019-11500)");

  script_tag(name:"affected", value:"'dovecot' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"dovecot", rpm:"dovecot~2.2.10~5.h6", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-mysql", rpm:"dovecot-mysql~2.2.10~5.h6", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-pgsql", rpm:"dovecot-pgsql~2.2.10~5.h6", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-pigeonhole", rpm:"dovecot-pigeonhole~2.2.10~5.h6", rls:"EULEROS-2.0SP2"))) {
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
