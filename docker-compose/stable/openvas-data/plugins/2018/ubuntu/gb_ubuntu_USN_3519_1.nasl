###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for tomcat8 USN-3519-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.843407");
  script_version("2021-06-07T02:00:27+0000");
  script_tag(name:"last_modification", value:"2021-06-07 02:00:27 +0000 (Mon, 07 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-01-09 10:10:39 +0100 (Tue, 09 Jan 2018)");
  script_cve_id("CVE-2017-5647", "CVE-2017-5648", "CVE-2017-5664", "CVE-2017-7674");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-20 21:15:00 +0000 (Mon, 20 Jul 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for tomcat8 USN-3519-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat8'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"It was discovered that Tomcat incorrectly
  handled certain pipelined requests when sendfile was used. A remote attacker
  could use this issue to obtain wrong responses possibly containing sensitive
  information. (CVE-2017-5647) It was discovered that Tomcat incorrectly used the
  appropriate facade object. A malicious application could possibly use this to
  bypass Security Manager restrictions. (CVE-2017-5648) It was discovered that
  Tomcat incorrectly handled error pages. A remote attacker could possibly use
  this issue to replace or remove the custom error page. (CVE-2017-5664) It was
  discovered that Tomcat incorrectly handled the CORS filter. A remote attacker
  could possibly use this issue to perform cache poisoning. (CVE-2017-7674)");
  script_tag(name:"affected", value:"tomcat8 on Ubuntu 17.04,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"USN", value:"3519-1");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3519-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|17\.04|16\.04 LTS)");

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

  if ((res = isdpkgvuln(pkg:"libtomcat7-java", ver:"7.0.52-1ubuntu0.13", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"tomcat7", ver:"7.0.52-1ubuntu0.13", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU17.04")
{

  if ((res = isdpkgvuln(pkg:"libtomcat8-java", ver:"8.0.38-2ubuntu2.2", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"tomcat8", ver:"8.0.38-2ubuntu2.2", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libtomcat8-java", ver:"8.0.32-1ubuntu1.5", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"tomcat8", ver:"8.0.32-1ubuntu1.5", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
