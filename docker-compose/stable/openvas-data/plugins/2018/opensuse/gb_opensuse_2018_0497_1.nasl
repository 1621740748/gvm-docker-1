# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851707");
  script_version("2021-06-28T11:00:33+0000");
  script_tag(name:"last_modification", value:"2021-06-28 11:00:33 +0000 (Mon, 28 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-02-21 08:47:44 +0100 (Wed, 21 Feb 2018)");
  script_cve_id("CVE-2016-1372", "CVE-2017-17969", "CVE-2018-5996");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-21 20:29:00 +0000 (Thu, 21 Mar 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for p7zip (openSUSE-SU-2018:0497-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'p7zip'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for p7zip fixes the following security issues:

  - CVE-2016-1372: Fixed multiple vulnerabilities when processing crafted 7z
  files (bsc#984650)

  - CVE-2017-17969: Fixed a heap-based buffer overflow in a shrink decoder
  (bsc#1077725)

  - CVE-2018-5996: Fixed memory corruption in RAR decompression. The
  complete RAR decoder was removed as it also has license issues
  (bsc#1077724 bsc#1077978)

  This update was imported from the SUSE:SLE-12:Update update project.");

  script_tag(name:"affected", value:"p7zip on openSUSE Leap 42.3");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2018:0497-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-02/msg00040.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.3") {
  if(!isnull(res = isrpmvuln(pkg:"p7zip", rpm:"p7zip~9.20.1~18.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p7zip-debuginfo", rpm:"p7zip-debuginfo~9.20.1~18.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p7zip-debugsource", rpm:"p7zip-debugsource~9.20.1~18.3.1", rls:"openSUSELeap42.3"))) {
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
