###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux-azure USN-3820-3
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.843820");
  script_version("2021-06-03T11:00:21+0000");
  script_cve_id("CVE-2018-15471", "CVE-2017-13168", "CVE-2018-16658", "CVE-2018-9363");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-06-03 11:00:21 +0000 (Thu, 03 Jun 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-11-15 05:59:13 +0100 (Thu, 15 Nov 2018)");
  script_name("Ubuntu Update for linux-azure USN-3820-3");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04 LTS");

  script_xref(name:"USN", value:"3820-3");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3820-3/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure'
  package(s) announced via the USN-3820-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Felix Wilhelm discovered that the Xen netback driver in the Linux kernel
did not properly perform input validation in some situations. An attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2018-15471)

It was discovered that the generic SCSI driver in the Linux kernel did not
properly enforce permissions on kernel memory access. A local attacker
could use this to expose sensitive information or possibly elevate
privileges. (CVE-2017-13168)

It was discovered that an integer overflow existed in the CD-ROM driver of
the Linux kernel. A local attacker could use this to expose sensitive
information (kernel memory). (CVE-2018-16658)

It was discovered that an integer overflow existed in the HID Bluetooth
implementation in the Linux kernel that could lead to a buffer overwrite.
An attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2018-9363)");

  script_tag(name:"affected", value:"linux-azure on Ubuntu 14.04 LTS.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-4.15.0-1031-azure", ver:"4.15.0-1031.32~14.04.1+signed1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-azure", ver:"4.15.0.1031.18", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
