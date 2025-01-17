###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for libtasn1-6 USN-2294-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.841911");
  script_version("2020-11-19T10:53:01+0000");
  script_tag(name:"last_modification", value:"2020-11-19 10:53:01 +0000 (Thu, 19 Nov 2020)");
  script_tag(name:"creation_date", value:"2014-07-28 16:39:15 +0530 (Mon, 28 Jul 2014)");
  script_cve_id("CVE-2014-3467", "CVE-2014-3468", "CVE-2014-3469");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Ubuntu Update for libtasn1-6 USN-2294-1");

  script_tag(name:"affected", value:"libtasn1-6 on Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS,
  Ubuntu 10.04 LTS");
  script_tag(name:"insight", value:"It was discovered that Libtasn1 incorrectly handled certain
ASN.1 data structures. An attacker could exploit this with specially crafted
ASN.1 data and cause applications using Libtasn1 to crash, resulting in a denial
of service. (CVE-2014-3467)

It was discovered that Libtasn1 incorrectly handled negative bit lengths.
An attacker could exploit this with specially crafted ASN.1 data and cause
applications using Libtasn1 to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2014-3468)

It was discovered that Libtasn1 incorrectly handled certain ASN.1 data. An
attacker could exploit this with specially crafted ASN.1 data and cause
applications using Libtasn1 to crash, resulting in a denial of service.
(CVE-2014-3469)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"USN", value:"2294-1");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2294-1/");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libtasn1-6'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|12\.04 LTS|10\.04 LTS)");

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

  if ((res = isdpkgvuln(pkg:"libtasn1-6:i386", ver:"3.4-3ubuntu0.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libtasn1-3", ver:"2.10-1ubuntu1.2", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libtasn1-3", ver:"2.4-1ubuntu0.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
