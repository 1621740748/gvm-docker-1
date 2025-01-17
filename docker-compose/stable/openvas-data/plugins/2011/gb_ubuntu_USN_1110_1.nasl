###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for kde4libs USN-1110-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1110-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.840656");
  script_version("2020-11-12T12:15:05+0000");
  script_tag(name:"last_modification", value:"2020-11-12 12:15:05 +0000 (Thu, 12 Nov 2020)");
  script_tag(name:"creation_date", value:"2011-05-10 14:04:15 +0200 (Tue, 10 May 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_xref(name:"USN", value:"1110-1");
  script_cve_id("CVE-2011-1094", "CVE-2011-1168");
  script_name("Ubuntu Update for kde4libs USN-1110-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04 LTS|9\.10|10\.10)");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1110-1");
  script_tag(name:"affected", value:"kde4libs on Ubuntu 10.10,
  Ubuntu 10.04 LTS,
  Ubuntu 9.10");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"It was discovered that KDE KSSL did not properly verify X.509 certificates
  when the certificate was issued for an IP address. An attacker could
  exploit this to perform a man in the middle attack to view sensitive
  information or alter encrypted communications. (CVE-2011-1094)

  Tim Brown discovered that KDE KHTML did not properly escape URLs from
  externally generated error pages. An attacker could exploit this to conduct
  cross-site scripting attacks. With cross-site scripting vulnerabilities, if
  a user were tricked into viewing server output during a crafted server
  request, a remote attacker could exploit this to modify the contents, or
  steal confidential data (such as passwords), within the same domain.
  (CVE-2011-1168)");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"kdelibs5", ver:"4:4.4.5-0ubuntu1.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU9.10")
{

  if ((res = isdpkgvuln(pkg:"kdelibs5", ver:"4:4.3.2-0ubuntu7.3", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"libkhtml5", ver:"4:4.5.1-0ubuntu8.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libkio5", ver:"4:4.5.1-0ubuntu8.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
