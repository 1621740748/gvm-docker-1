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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2232.1");
  script_cve_id("CVE-2018-0360", "CVE-2018-0361");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:39 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-07-22T02:21:52+0000");
  script_tag(name:"last_modification", value:"2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-26 16:41:00 +0000 (Fri, 26 Apr 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2232-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4|SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2232-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182232-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav' package(s) announced via the SUSE-SU-2018:2232-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for clamav to version 0.100.1 fixes the following issues:
The following security vulnerabilities were addressed:
- CVE-2018-0360: HWP integer overflow, infinite loop vulnerability
 (bsc#1101410)
- CVE-2018-0361: PDF object length check, unreasonably long time to parse
 relatively small file (bsc#1101412)
- Buffer over-read in unRAR code due to missing max value checks in table
 initialization
- Libmspack heap buffer over-read in CHM parser (bsc#1103040)
- PDF parser bugs The following other changes were made:
- Disable YARA support for licensing reasons (bsc#1101654).
- Add HTTPS support for clamsubmit
- Fix for DNS resolution for users on IPv4-only machines where IPv6 is not
 available or is link-local only");

  script_tag(name:"affected", value:"'clamav' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Debuginfo 11-SP3.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.100.1~0.20.15.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.100.1~0.20.15.1", rls:"SLES11.0SP3"))) {
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
