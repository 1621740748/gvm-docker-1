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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2340");
  script_version("2021-08-02T02:00:56+0000");
  script_cve_id("CVE-2017-10789");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-08-02 02:00:56 +0000 (Mon, 02 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2020-01-23 12:47:33 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for perl-DBD-MySQL (EulerOS-SA-2019-2340)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64-3\.0\.3\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2340");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2340");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'perl-DBD-MySQL' package(s) announced via the EulerOS-SA-2019-2340 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The DBD::mysql module through 4.043 for Perl uses the mysql_ssl=1 setting to mean that SSL is optional (even though this setting's documentation has a 'your communication with the server will be encrypted' statement), which allows man-in-the-middle attackers to spoof servers via a cleartext-downgrade attack, a related issue to CVE-2015-3152.(CVE-2017-10789)");

  script_tag(name:"affected", value:"'perl-DBD-MySQL' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.3.0.");

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

if(release == "EULEROSVIRTARM64-3.0.3.0") {

  if(!isnull(res = isrpmvuln(pkg:"perl-DBD-MySQL", rpm:"perl-DBD-MySQL~4.046~4.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.3.0"))) {
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
