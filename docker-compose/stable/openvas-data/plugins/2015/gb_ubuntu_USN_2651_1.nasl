###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for patch USN-2651-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842253");
  script_version("2019-12-12T07:51:40+0000");
  script_tag(name:"last_modification", value:"2019-12-12 07:51:40 +0000 (Thu, 12 Dec 2019)");
  script_tag(name:"creation_date", value:"2015-06-24 06:17:46 +0200 (Wed, 24 Jun 2015)");
  script_cve_id("CVE-2010-4651", "CVE-2014-9637", "CVE-2015-1196", "CVE-2015-1395",
                "CVE-2015-1396");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for patch USN-2651-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'patch'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Jakub Wilk discovered that GNU patch did
not correctly handle file paths in patch files. An attacker could specially craft
a patch file that could overwrite arbitrary files with the privileges of the user
invoking the program. This issue only affected Ubuntu 12.04 LTS. (CVE-2010-4651)

L&#225 szl&#243  B&#246 sz&#246 rm&#233 nyi discovered that GNU patch did not
correctly handle some patch files. An attacker could specially craft a patch file
that could cause a denial of service. (CVE-2014-9637)

Jakub Wilk discovered that GNU patch did not correctly handle symbolic links in
git style patch files. An attacker could specially craft a patch file that
could overwrite arbitrary files with the privileges of the user invoking the
program. This issue only affected Ubuntu 14.04 LTS and Ubuntu 14.10.
(CVE-2015-1196)

Jakub Wilk discovered that GNU patch did not correctly handle file renames in
git style patch files. An attacker could specially craft a patch file that
could overwrite arbitrary files with the privileges of the user invoking the
program. This issue only affected Ubuntu 14.04 LTS and Ubuntu 14.10.
(CVE-2015-1395)

Jakub Wilk discovered the fix for CVE-2015-1196 was incomplete for GNU patch.
An attacker could specially craft a patch file that could overwrite arbitrary
files with the privileges of the user invoking the program. This issue only
affected Ubuntu 14.04 LTS and Ubuntu 14.10. (CVE-2015-1396)");
  script_tag(name:"affected", value:"patch on Ubuntu 14.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"USN", value:"2651-1");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2651-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.10|14\.04 LTS|12\.04 LTS)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU14.10")
{

  if ((res = isdpkgvuln(pkg:"patch", ver:"2.7.1-5ubuntu0.3", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"patch", ver:"2.7.1-4ubuntu2.3", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"patch", ver:"2.6.1-3ubuntu0.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
