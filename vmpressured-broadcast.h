/*
 * SPDX-License-Identifier: GPL-2.0
 * SPDX-FileCopyrightText: Copyright (C) 2026 Edera, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see
 * <https://www.gnu.org/licenses/>.
 */

#pragma once

struct vmpressure_broadcaster;

extern int vmpressure_broadcaster_init(struct vmpressure_broadcaster **out,
				       const char *listen_path);

extern void vmpressure_broadcaster_fini(struct vmpressure_broadcaster *broadcaster);

extern void vmpressure_broadcaster_send(struct vmpressure_broadcaster *broadcaster,
					const char *buf, ...);

extern int vmpressure_broadcaster_fd(struct vmpressure_broadcaster *broadcaster);

extern int vmpressure_broadcaster_accept(struct vmpressure_broadcaster *broadcaster);
