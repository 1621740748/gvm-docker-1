###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux-azure USN-3752-3
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
  script_oid("1.3.6.1.4.1.25623.1.0.843630");
  script_version("2021-06-04T11:00:20+0000");
  script_tag(name:"last_modification", value:"2021-06-04 11:00:20 +0000 (Fri, 04 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-08-29 07:13:34 +0200 (Wed, 29 Aug 2018)");
  script_cve_id("CVE-2018-1000200", "CVE-2018-10323", "CVE-2018-10840", "CVE-2018-10881",
                "CVE-2018-1093", "CVE-2018-1108", "CVE-2018-1120", "CVE-2018-11412",
                "CVE-2018-11506", "CVE-2018-12232", "CVE-2018-12233", "CVE-2018-12904",
                "CVE-2018-13094", "CVE-2018-13405", "CVE-2018-13406", "CVE-2018-5814",
                "CVE-2018-9415", "CVE-2018-1000204");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-28 15:04:00 +0000 (Fri, 28 Aug 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for linux-azure USN-3752-3");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
the target host.");
  script_tag(name:"insight", value:"It was discovered that, when attempting to handle an
out-of-memory situation, a null pointer dereference could be triggered in the Linux
kernel in some circumstances. A local attacker could use this to cause a
denial of service (system crash). (CVE-2018-1000200)

Wen Xu discovered that the XFS filesystem implementation in the Linux
kernel did not properly validate meta-data information. An attacker could
use this to construct a malicious xfs image that, when mounted, could cause
a denial of service (system crash). (CVE-2018-10323)

Wen Xu discovered that the XFS filesystem implementation in the Linux
kernel did not properly validate xattr information. An attacker could use
this to construct a malicious xfs image that, when mounted, could cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2018-10840)

Wen Xu discovered that the ext4 filesystem implementation in the Linux
kernel did not properly keep meta-data information consistent in some
situations. An attacker could use this to construct a malicious ext4 image
that, when mounted, could cause a denial of service (system crash).
(CVE-2018-10881)

Wen Xu discovered that the ext4 filesystem implementation in the Linux
kernel did not properly handle corrupted meta data in some situations. An
attacker could use this to specially craft an ext4 filesystem that caused a
denial of service (system crash) when mounted. (CVE-2018-1093)

Jann Horn discovered that the Linux kernel's implementation of random seed
data reported that it was in a ready state before it had gathered
sufficient entropy. An attacker could use this to expose sensitive
information. (CVE-2018-1108)

It was discovered that the procfs filesystem did not properly handle
processes mapping some memory elements onto files. A local attacker could
use this to block utilities that examine the procfs filesystem to report
operating system state, such as ps(1). (CVE-2018-1120)

Jann Horn discovered that the ext4 filesystem implementation in the Linux
kernel did not properly keep xattr information consistent in some
situations. An attacker could use this to construct a malicious ext4 image
that, when mounted, could cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2018-11412)

Piotr Gabriel Kosinski and Daniel Shapira discovered a stack-based buffer
overflow in the CDROM driver implementation of the Linux kernel. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2018-11506)

Shankara Pailoor discovered that a race condition existed in the  ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"linux-azure on Ubuntu 18.04 LTS,
  Ubuntu 16.04 LTS");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"USN", value:"3752-3");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3752-3/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04 LTS|16\.04 LTS)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU18.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-4.15.0-1017-oem", ver:"4.15.0-1017.20", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.15.0-1022-azure", ver:"4.15.0-1022.23", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-azure", ver:"4.15.0.1022.22", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-azure-edge", ver:"4.15.0.1022.22", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-oem", ver:"4.15.0.1017.19", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-4.15.0-1018-gcp", ver:"4.15.0-1018.19~16.04.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.15.0-1022-azure", ver:"4.15.0-1022.22~16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-azure", ver:"4.15.0.1022.28", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-gcp", ver:"4.15.0.1018.32", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-gke", ver:"4.15.0.1018.32", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
