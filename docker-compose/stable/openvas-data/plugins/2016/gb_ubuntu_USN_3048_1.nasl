###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for curl USN-3048-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.842849");
  script_version("2020-05-14T09:33:44+0000");
  script_tag(name:"last_modification", value:"2020-05-14 09:33:44 +0000 (Thu, 14 May 2020)");
  script_tag(name:"creation_date", value:"2016-08-09 05:35:24 +0200 (Tue, 09 Aug 2016)");
  script_cve_id("CVE-2016-5419", "CVE-2016-5420", "CVE-2016-5421");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for curl USN-3048-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Bru Rom discovered that curl incorrectly
  handled client certificates when resuming a TLS session. (CVE-2016-5419)

It was discovered that curl incorrectly handled client certificates when
reusing TLS connections. (CVE-2016-5420)

Marcelo Echeverria and Fernando Mu&#241 oz discovered that curl incorrectly
reused a connection struct, contrary to expectations. This issue only
applied to Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2016-5421)");
  script_tag(name:"affected", value:"curl on Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"USN", value:"3048-1");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3048-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|12\.04 LTS|16\.04 LTS)");

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

  if ((res = isdpkgvuln(pkg:"libcurl3:i386", ver:"7.35.0-1ubuntu2.8", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3:amd64", ver:"7.35.0-1ubuntu2.8", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3-gnutls:i386", ver:"7.35.0-1ubuntu2.8", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3-gnutls:amd64", ver:"7.35.0-1ubuntu2.8", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3-nss:i386", ver:"7.35.0-1ubuntu2.8", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3-nss:amd64", ver:"7.35.0-1ubuntu2.8", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libcurl3:i386", ver:"7.22.0-3ubuntu4.16", rls:"UBUNTU12.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3:amd64", ver:"7.22.0-3ubuntu4.16", rls:"UBUNTU12.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3-gnutls:i386", ver:"7.22.0-3ubuntu4.16", rls:"UBUNTU12.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3-gnutls:amd64", ver:"7.22.0-3ubuntu4.16", rls:"UBUNTU12.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3-nss:i386", ver:"7.22.0-3ubuntu4.16", rls:"UBUNTU12.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3-nss:amd64", ver:"7.22.0-3ubuntu4.16", rls:"UBUNTU12.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libcurl3:i386", ver:"7.47.0-1ubuntu2.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3:amd64", ver:"7.47.0-1ubuntu2.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3-gnutls:i386", ver:"7.47.0-1ubuntu2.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3-gnutls:amd64", ver:"7.47.0-1ubuntu2.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3-nss:i386", ver:"7.47.0-1ubuntu2.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcurl3-nss:amd64", ver:"7.47.0-1ubuntu2.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}