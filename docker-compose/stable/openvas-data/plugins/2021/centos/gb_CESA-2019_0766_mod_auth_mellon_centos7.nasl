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
  script_oid("1.3.6.1.4.1.25623.1.0.883036");
  script_version("2021-05-27T07:09:59+0000");
  script_cve_id("CVE-2019-3877", "CVE-2019-3878");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-05-27 07:09:59 +0000 (Thu, 27 May 2021)");
  script_tag(name:"creation_date", value:"2021-04-21 14:10:46 +0000 (Wed, 21 Apr 2021)");
  script_name("CentOS: Security Advisory for mod_auth_mellon (CESA-2019:0766)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2019:0766");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2019-April/023270.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mod_auth_mellon'
  package(s) announced via the CESA-2019:0766 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The mod_auth_mellon module for the Apache HTTP Server is an authentication
service that implements the SAML 2.0 federation protocol. The module grants
access based on the attributes received in assertions generated by an IdP
server.

Security Fix(es):

  * mod_auth_mellon: authentication bypass in ECP flow (CVE-2019-3878)

  * mod_auth_mellon: open redirect in logout url when using URLs with
backslashes (CVE-2019-3877)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * mod_auth_mellon Cert files name wrong when hostname contains a number
(fixed in upstream package) (BZ#1697487)");

  script_tag(name:"affected", value:"'mod_auth_mellon' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"mod_auth_mellon", rpm:"mod_auth_mellon~0.14.0~2.el7_6.4", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_auth_mellon-diagnostics", rpm:"mod_auth_mellon-diagnostics~0.14.0~2.el7_6.4", rls:"CentOS7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);