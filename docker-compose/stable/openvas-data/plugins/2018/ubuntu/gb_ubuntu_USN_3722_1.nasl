###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for clamav USN-3722-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.843598");
  script_version("2021-06-04T02:00:20+0000");
  script_tag(name:"last_modification", value:"2021-06-04 02:00:20 +0000 (Fri, 04 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-07-25 06:03:12 +0200 (Wed, 25 Jul 2018)");
  script_cve_id("CVE-2018-0360", "CVE-2018-0361");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-26 16:41:00 +0000 (Fri, 26 Apr 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for clamav USN-3722-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
on the target host.");
  script_tag(name:"insight", value:"It was discovered that ClamAV incorrectly
handled parsing certain HWP files. A remote attacker could use this issue to
cause ClamAV to hang, resulting in a denial of service. (CVE-2018-0360)

It was discovered that ClamAV incorrectly handled parsing certain PDF
files. A remote attacker could use this issue to cause ClamAV to hang,
resulting in a denial of service. (CVE-2018-0361)");
  script_tag(name:"affected", value:"clamav on Ubuntu 18.04 LTS,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"USN", value:"3722-1");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3722-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|18\.04 LTS|16\.04 LTS)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"clamav", ver:"0.100.1+dfsg-1ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU18.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"clamav", ver:"0.100.1+dfsg-1ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"clamav", ver:"0.100.1+dfsg-1ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
