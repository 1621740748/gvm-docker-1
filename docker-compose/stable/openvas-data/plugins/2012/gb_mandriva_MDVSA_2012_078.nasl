###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for imagemagick MDVSA-2012:078 (imagemagick)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:078");
  script_oid("1.3.6.1.4.1.25623.1.0.831591");
  script_version("2020-08-04T07:16:50+0000");
  script_tag(name:"last_modification", value:"2020-08-04 07:16:50 +0000 (Tue, 04 Aug 2020)");
  script_tag(name:"creation_date", value:"2012-08-03 09:51:09 +0530 (Fri, 03 Aug 2012)");
  script_cve_id("CVE-2012-0247", "CVE-2012-0248", "CVE-2012-1185", "CVE-2012-0259", "CVE-2012-0260", "CVE-2012-1798");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"MDVSA", value:"2012:078");
  script_name("Mandriva Update for imagemagick MDVSA-2012:078 (imagemagick)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'imagemagick'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_2011\.0");
  script_tag(name:"affected", value:"imagemagick on Mandriva Linux 2011.0");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been found and corrected in imagemagick:

  A flaw was found in the way ImageMagick processed images with malformed
  Exchangeable image file format (Exif) metadata. An attacker could
  create a specially-crafted image file that, when opened by a victim,
  would cause ImageMagick to crash or, potentially, execute arbitrary
  code (CVE-2012-0247).

  The updated packages have been patched to correct these issues.

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MNDK_2011.0")
{

  if ((res = isrpmvuln(pkg:"imagemagick", rpm:"imagemagick~6.7.0.9~1.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"imagemagick-desktop", rpm:"imagemagick-desktop~6.7.0.9~1.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"imagemagick-doc", rpm:"imagemagick-doc~6.7.0.9~1.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmagick4", rpm:"libmagick4~6.7.0.9~1.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmagick-devel", rpm:"libmagick-devel~6.7.0.9~1.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-Image-Magick", rpm:"perl-Image-Magick~6.7.0.9~1.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64magick4", rpm:"lib64magick4~6.7.0.9~1.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64magick-devel", rpm:"lib64magick-devel~6.7.0.9~1.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
