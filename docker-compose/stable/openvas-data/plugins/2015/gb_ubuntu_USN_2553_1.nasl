###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for tiff USN-2553-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.842150");
  script_version("2020-02-18T15:18:54+0000");
  script_tag(name:"last_modification", value:"2020-02-18 15:18:54 +0000 (Tue, 18 Feb 2020)");
  script_tag(name:"creation_date", value:"2015-04-01 07:25:08 +0200 (Wed, 01 Apr 2015)");
  script_cve_id("CVE-2014-8127", "CVE-2014-8128", "CVE-2014-8129", "CVE-2014-8130",
                "CVE-2014-9330", "CVE-2014-9655");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for tiff USN-2553-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'tiff'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"William Robinet discovered that LibTIFF
incorrectly handled certain malformed images. If a user or automated system were
tricked into opening a specially crafted image, a remote attacker could crash the
application, leading to a denial of service, or possibly execute arbitrary code
with user privileges. (CVE-2014-8127, CVE-2014-8128, CVE-2014-8129,
CVE-2014-8130)

Paris Zoumpouloglou discovered that LibTIFF incorrectly handled certain
malformed BMP images. If a user or automated system were tricked into
opening a specially crafted BMP image, a remote attacker could crash the
application, leading to a denial of service. (CVE-2014-9330)

Michal Zalewski discovered that LibTIFF incorrectly handled certain
malformed images. If a user or automated system were tricked into opening a
specially crafted image, a remote attacker could crash the application,
leading to a denial of service, or possibly execute arbitrary code with
user privileges. (CVE-2014-9655)");
  script_tag(name:"affected", value:"tiff on Ubuntu 14.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS,
  Ubuntu 10.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"USN", value:"2553-1");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2553-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.10|14\.04 LTS|12\.04 LTS|10\.04 LTS)");

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

  if ((res = isdpkgvuln(pkg:"libtiff5:amd64", ver:"4.0.3-10ubuntu0.1", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libtiff5:i386", ver:"4.0.3-10ubuntu0.1", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libtiff5:i386", ver:"4.0.3-7ubuntu0.2", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libtiff5:amd64", ver:"4.0.3-7ubuntu0.2", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libtiff4", ver:"3.9.5-2ubuntu1.7", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libtiff4", ver:"3.9.2-2ubuntu0.15", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
