# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851211");
  script_version("2020-06-03T08:38:58+0000");
  script_tag(name:"last_modification", value:"2020-06-03 08:38:58 +0000 (Wed, 03 Jun 2020)");
  script_tag(name:"creation_date", value:"2016-03-01 11:08:51 +0530 (Tue, 01 Mar 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_cve_id("CVE-2016-4007");
  script_name("openSUSE: Security Advisory for obs-service-download_files (openSUSE-SU-2016:0521-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'obs-service-download_files'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for a number of source services fixes the following issues:

  - boo#967265: Various code/parameter injection issues could have allowed
  malicious service definition to execute commands or make changes to the
  user's file system

  The following source services are affected

  - obs-service-source_validator

  - obs-service-extract_file

  - obs-service-download_files

  - obs-service-recompress

  - obs-service-verify_file

  Also contains all bug fixes and improvements from the openSUSE:Tools
  versions.");

  script_tag(name:"affected", value:"obs-service-download_files, on openSUSE 13.2");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2016:0521-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE13.2")
{

  if(!isnull(res = isrpmvuln(pkg:"obs-service-download_files", rpm:"obs-service-download_files~0.5.1.git.1455712026.9c0a4a0~2.6.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"obs-service-extract_file", rpm:"obs-service-extract_file~0.3~3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"obs-service-recompress", rpm:"obs-service-recompress~0.3.1+git20160217.7897d3f~3.3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"obs-service-source_validator", rpm:"obs-service-source_validator~0.6+git20160218.73d6618~3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"obs-service-verify_file", rpm:"obs-service-verify_file~0.1.1~12.3.1", rls:"openSUSE13.2"))) {
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
