/*
 Navicat Premium Data Transfer

 Source Server         : 学生信息管理系统
 Source Server Type    : MySQL
 Source Server Version : 80036
 Source Host           : localhost:3306
 Source Schema         : risk_assessment

 Target Server Type    : MySQL
 Target Server Version : 80036
 File Encoding         : 65001

 Date: 21/04/2025 15:16:10
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for feature_stats
-- ----------------------------
DROP TABLE IF EXISTS `feature_stats`;
CREATE TABLE `feature_stats`  (
  `id` int NOT NULL AUTO_INCREMENT,
  `feature_type` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `feature_value` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `user_id` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL,
  `count` int NOT NULL DEFAULT 0,
  `first_seen` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `last_seen` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `idx_unique_feature`(`feature_type` ASC, `feature_value` ASC, `user_id` ASC) USING BTREE,
  INDEX `idx_feature_type`(`feature_type` ASC) USING BTREE,
  INDEX `idx_user_id`(`user_id` ASC) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 1 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of feature_stats
-- ----------------------------
INSERT INTO `feature_stats` VALUES (1, 'ip', '::ffff:127.0.0.1', NULL, 11, '2025-03-21 20:05:30', '2025-03-30 22:31:04');
INSERT INTO `feature_stats` VALUES (2, 'ip', '::1', NULL, 64, '2025-03-21 20:25:10', '2025-04-20 17:07:22');
INSERT INTO `feature_stats` VALUES (4, 'ip', '::ffff:127.0.0.1', '1740483425007', 9, '2025-03-21 20:05:30', '2025-03-21 21:31:55');
INSERT INTO `feature_stats` VALUES (5, 'ip', '::1', '1740483425007', 55, '2025-03-21 20:25:10', '2025-04-20 17:07:22');
INSERT INTO `feature_stats` VALUES (6, 'ip', '::1', '1742727893857', 9, '2025-03-23 19:05:01', '2025-03-23 19:06:57');
INSERT INTO `feature_stats` VALUES (7, 'ip', '::ffff:127.0.0.1', '1743344781652', 2, '2025-03-30 22:26:57', '2025-03-30 22:31:04');
INSERT INTO `feature_stats` VALUES (11, 'ua', 'Mozilla', NULL, 73, '2025-03-21 20:05:30', '2025-04-20 17:07:22');
INSERT INTO `feature_stats` VALUES (12, 'ua', 'Unknown', NULL, 2, '2025-03-21 20:09:51', '2025-03-21 21:09:13');
INSERT INTO `feature_stats` VALUES (14, 'ua', 'Mozilla', '1740483425007', 62, '2025-03-21 20:05:30', '2025-04-20 17:07:22');
INSERT INTO `feature_stats` VALUES (15, 'ua', 'Unknown', '1740483425007', 2, '2025-03-21 20:09:51', '2025-03-21 21:09:13');
INSERT INTO `feature_stats` VALUES (16, 'ua', 'Mozilla', '1742727893857', 9, '2025-03-23 19:05:01', '2025-03-23 19:06:57');
INSERT INTO `feature_stats` VALUES (17, 'ua', 'Mozilla', '1743344781652', 2, '2025-03-30 22:26:57', '2025-03-30 22:31:04');
INSERT INTO `feature_stats` VALUES (21, 'bv', '5.0', NULL, 73, '2025-03-21 20:05:30', '2025-04-20 17:07:22');
INSERT INTO `feature_stats` VALUES (22, 'bv', 'Unknown', NULL, 2, '2025-03-21 20:09:51', '2025-03-21 21:09:13');
INSERT INTO `feature_stats` VALUES (24, 'bv', '5.0', '1740483425007', 62, '2025-03-21 20:05:30', '2025-04-20 17:07:22');
INSERT INTO `feature_stats` VALUES (25, 'bv', 'Unknown', '1740483425007', 2, '2025-03-21 20:09:51', '2025-03-21 21:09:13');
INSERT INTO `feature_stats` VALUES (26, 'bv', '5.0', '1742727893857', 9, '2025-03-23 19:05:01', '2025-03-23 19:06:57');
INSERT INTO `feature_stats` VALUES (27, 'bv', '5.0', '1743344781652', 2, '2025-03-30 22:26:57', '2025-03-30 22:31:04');
INSERT INTO `feature_stats` VALUES (31, 'osv', 'Windows NT 10.0', NULL, 59, '2025-03-21 20:05:30', '2025-04-20 17:07:22');
INSERT INTO `feature_stats` VALUES (32, 'osv', 'Unknown', NULL, 8, '2025-03-21 20:09:51', '2025-03-23 19:05:32');
INSERT INTO `feature_stats` VALUES (33, 'osv', 'Linux', NULL, 5, '2025-03-21 20:25:10', '2025-03-23 19:06:57');
INSERT INTO `feature_stats` VALUES (34, 'osv', 'Android 4.4', NULL, 2, '2025-03-21 21:17:46', '2025-03-21 21:25:48');
INSERT INTO `feature_stats` VALUES (35, 'osv', 'Mac OS X Mozilla/5.0 (iPad; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1', NULL, 1, '2025-03-21 21:48:54', '2025-03-21 21:48:54');
INSERT INTO `feature_stats` VALUES (38, 'osv', 'Windows NT 10.0', '1740483425007', 50, '2025-03-21 20:05:30', '2025-04-20 17:07:22');
INSERT INTO `feature_stats` VALUES (39, 'osv', 'Unknown', '1740483425007', 7, '2025-03-21 20:09:51', '2025-03-23 18:47:54');
INSERT INTO `feature_stats` VALUES (40, 'osv', 'Linux', '1740483425007', 4, '2025-03-21 20:25:10', '2025-03-22 11:35:39');
INSERT INTO `feature_stats` VALUES (41, 'osv', 'Android 4.4', '1740483425007', 2, '2025-03-21 21:17:46', '2025-03-21 21:25:48');
INSERT INTO `feature_stats` VALUES (42, 'osv', 'Mac OS X Mozilla/5.0 (iPad; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1', '1740483425007', 1, '2025-03-21 21:48:54', '2025-03-21 21:48:54');
INSERT INTO `feature_stats` VALUES (43, 'osv', 'Windows NT 10.0', '1742727893857', 7, '2025-03-23 19:05:01', '2025-03-23 19:05:56');
INSERT INTO `feature_stats` VALUES (44, 'osv', 'Unknown', '1742727893857', 1, '2025-03-23 19:05:32', '2025-03-23 19:05:32');
INSERT INTO `feature_stats` VALUES (45, 'osv', 'Linux', '1742727893857', 1, '2025-03-23 19:06:57', '2025-03-23 19:06:57');
INSERT INTO `feature_stats` VALUES (46, 'osv', 'Windows NT 10.0', '1743344781652', 2, '2025-03-30 22:26:57', '2025-03-30 22:31:04');
INSERT INTO `feature_stats` VALUES (53, 'df', 'desktop', NULL, 61, '2025-03-21 20:05:30', '2025-04-20 17:07:22');
INSERT INTO `feature_stats` VALUES (54, 'df', 'mobile', NULL, 14, '2025-03-21 20:25:10', '2025-03-23 19:06:57');
INSERT INTO `feature_stats` VALUES (56, 'df', 'desktop', '1740483425007', 52, '2025-03-21 20:05:30', '2025-04-20 17:07:22');
INSERT INTO `feature_stats` VALUES (57, 'df', 'mobile', '1740483425007', 12, '2025-03-21 20:25:10', '2025-03-23 18:47:54');
INSERT INTO `feature_stats` VALUES (58, 'df', 'desktop', '1742727893857', 7, '2025-03-23 19:05:01', '2025-03-23 19:05:56');
INSERT INTO `feature_stats` VALUES (59, 'df', 'mobile', '1742727893857', 2, '2025-03-23 19:05:32', '2025-03-23 19:06:57');
INSERT INTO `feature_stats` VALUES (60, 'df', 'desktop', '1743344781652', 2, '2025-03-30 22:26:57', '2025-03-30 22:31:04');
INSERT INTO `feature_stats` VALUES (63, 'rtt', '0', NULL, 72, '2025-03-21 20:05:30', '2025-03-23 21:28:32');
INSERT INTO `feature_stats` VALUES (64, 'rtt', '139', NULL, 1, '2025-03-30 22:26:57', '2025-03-30 22:26:57');
INSERT INTO `feature_stats` VALUES (65, 'rtt', '298', NULL, 1, '2025-03-30 22:31:04', '2025-03-30 22:31:04');
INSERT INTO `feature_stats` VALUES (66, 'rtt', '207', NULL, 1, '2025-04-20 17:07:22', '2025-04-20 17:07:22');
INSERT INTO `feature_stats` VALUES (70, 'rtt', '0', '1740483425007', 63, '2025-03-21 20:05:30', '2025-03-23 21:28:32');
INSERT INTO `feature_stats` VALUES (71, 'rtt', '0', '1742727893857', 9, '2025-03-23 19:05:01', '2025-03-23 19:06:57');
INSERT INTO `feature_stats` VALUES (72, 'rtt', '139', '1743344781652', 1, '2025-03-30 22:26:57', '2025-03-30 22:26:57');
INSERT INTO `feature_stats` VALUES (73, 'rtt', '298', '1743344781652', 1, '2025-03-30 22:31:04', '2025-03-30 22:31:04');
INSERT INTO `feature_stats` VALUES (74, 'rtt', '207', '1740483425007', 1, '2025-04-20 17:07:22', '2025-04-20 17:07:22');
INSERT INTO `feature_stats` VALUES (77, 'asn', 'Unknown', NULL, 15, '2025-03-21 20:05:30', '2025-03-30 22:31:04');
INSERT INTO `feature_stats` VALUES (78, 'asn', 'Local', NULL, 58, '2025-03-21 21:09:13', '2025-04-20 17:07:22');
INSERT INTO `feature_stats` VALUES (80, 'asn', 'Unknown', '1740483425007', 13, '2025-03-21 20:05:30', '2025-03-21 21:31:55');
INSERT INTO `feature_stats` VALUES (81, 'asn', 'Local', '1740483425007', 49, '2025-03-21 21:09:13', '2025-04-20 17:07:22');
INSERT INTO `feature_stats` VALUES (82, 'asn', 'Local', '1742727893857', 9, '2025-03-23 19:05:01', '2025-03-23 19:06:57');
INSERT INTO `feature_stats` VALUES (83, 'asn', 'Unknown', '1743344781652', 2, '2025-03-30 22:26:57', '2025-03-30 22:31:04');

-- ----------------------------
-- Table structure for risk_logs
-- ----------------------------
DROP TABLE IF EXISTS `risk_logs`;
CREATE TABLE `risk_logs`  (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL,
  `ip_address` varchar(45) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `user_agent` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT '用户代理信息',
  `rtt` int NULL DEFAULT 0,
  `geo_data` json NULL,
  `risk_score` float NULL DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `action` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'ALLOW' COMMENT '处置动作: ALLOW/REJECT/CHALLENGE',
  PRIMARY KEY (`id`) USING BTREE,
  INDEX `idx_user`(`user_id` ASC) USING BTREE,
  INDEX `idx_created`(`created_at` ASC) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 80 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of risk_logs
-- ----------------------------
INSERT INTO `risk_logs` VALUES (5, '1740483425007', '::ffff:127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.97.2 Chrome/128.0.6613.186 Electron/32.2.7 Safari/537.36', 0, '{\"cc\": \"XX\", \"ip\": \"::ffff:127.0.0.1\", \"asn\": \"Unknown\"}', 0.175, '2025-03-21 20:05:30', 'ALLOW');
INSERT INTO `risk_logs` VALUES (6, '1740483425007', '::ffff:127.0.0.1', 'Unknown', 0, '{}', 0.175, '2025-03-21 20:09:51', 'ALLOW');
INSERT INTO `risk_logs` VALUES (7, '1740483425007', '::ffff:127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.97.2 Chrome/128.0.6613.186 Electron/32.2.7 Safari/537.36', 0, '{\"cc\": \"XX\", \"ip\": \"::ffff:127.0.0.1\", \"asn\": \"Unknown\"}', 0.175, '2025-03-21 20:09:51', 'ALLOW');
INSERT INTO `risk_logs` VALUES (8, '1740483425007', '::ffff:127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.97.2 Chrome/128.0.6613.186 Electron/32.2.7 Safari/537.36', 0, '{\"cc\": \"XX\", \"ip\": \"::ffff:127.0.0.1\", \"asn\": \"Unknown\"}', 0.175, '2025-03-21 20:10:56', 'ALLOW');
INSERT INTO `risk_logs` VALUES (9, '1740483425007', '::ffff:127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.97.2 Chrome/128.0.6613.186 Electron/32.2.7 Safari/537.36', 0, '{\"cc\": \"XX\", \"ip\": \"::ffff:127.0.0.1\", \"asn\": \"Unknown\"}', 0.175, '2025-03-21 20:14:36', 'ALLOW');
INSERT INTO `risk_logs` VALUES (10, '1740483425007', '::ffff:127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.97.2 Chrome/128.0.6613.186 Electron/32.2.7 Safari/537.36', 0, '{\"cc\": \"XX\", \"ip\": \"::ffff:127.0.0.1\", \"asn\": \"Unknown\"}', 0.0039, '2025-03-21 20:18:13', 'ALLOW');
INSERT INTO `risk_logs` VALUES (11, '1740483425007', '::1', 'Mozilla/5.0 (Linux; U; Android 2.3.6; en-us; Nexus S Build/GRK39F) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1', 0, '{\"cc\": \"XX\", \"ip\": \"::1\", \"asn\": \"Unknown\"}', 0.0046, '2025-03-21 20:25:10', 'ALLOW');
INSERT INTO `risk_logs` VALUES (12, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"XX\", \"ip\": \"::1\", \"asn\": \"Unknown\"}', 0.0063, '2025-03-21 20:39:07', 'ALLOW');
INSERT INTO `risk_logs` VALUES (13, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"XX\", \"ip\": \"::1\", \"asn\": \"Unknown\"}', 0.0089, '2025-03-21 20:39:20', 'ALLOW');
INSERT INTO `risk_logs` VALUES (14, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"XX\", \"ip\": \"::1\", \"asn\": \"Unknown\"}', 0.0131, '2025-03-21 20:39:46', 'ALLOW');
INSERT INTO `risk_logs` VALUES (15, '1740483425007', '::ffff:127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.97.2 Chrome/128.0.6613.186 Electron/32.2.7 Safari/537.36', 0, '{\"cc\": \"XX\", \"ip\": \"::ffff:127.0.0.1\", \"asn\": \"Unknown\"}', 0.0047, '2025-03-21 20:56:14', 'ALLOW');
INSERT INTO `risk_logs` VALUES (16, '1740483425007', '::ffff:127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.97.2 Chrome/128.0.6613.186 Electron/32.2.7 Safari/537.36', 0, '{\"cc\": \"XX\", \"ip\": \"::ffff:127.0.0.1\", \"asn\": \"Unknown\"}', 0.0002, '2025-03-21 21:00:38', 'ALLOW');
INSERT INTO `risk_logs` VALUES (17, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"XX\", \"ip\": \"::1\", \"asn\": \"Unknown\"}', 0.0002, '2025-03-21 21:06:02', 'ALLOW');
INSERT INTO `risk_logs` VALUES (18, '1740483425007', '::1', 'Unknown', 0, '{}', 0.00021875, '2025-03-21 21:09:13', 'ALLOW');
INSERT INTO `risk_logs` VALUES (19, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0.0002, '2025-03-21 21:09:13', 'ALLOW');
INSERT INTO `risk_logs` VALUES (20, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0, '2025-03-21 21:14:29', 'ALLOW');
INSERT INTO `risk_logs` VALUES (21, '1740483425007', '::1', 'Mozilla/5.0 (Linux; U; Android 2.3.6; en-us; Nexus S Build/GRK39F) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0.0001, '2025-03-21 21:15:42', 'ALLOW');
INSERT INTO `risk_logs` VALUES (22, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0, '2025-03-21 21:16:21', 'ALLOW');
INSERT INTO `risk_logs` VALUES (23, '1740483425007', '::1', 'Mozilla/5.0 (Android 4.4; Mobile; rv:70.0) Gecko/70.0 Firefox/70.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0, '2025-03-21 21:17:46', 'ALLOW');
INSERT INTO `risk_logs` VALUES (24, '1740483425007', '::1', 'Mozilla/5.0 (Android 4.4; Mobile; rv:70.0) Gecko/70.0 Firefox/70.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0, '2025-03-21 21:25:48', 'ALLOW');
INSERT INTO `risk_logs` VALUES (25, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0, '2025-03-21 21:27:32', 'ALLOW');
INSERT INTO `risk_logs` VALUES (26, '1740483425007', '::ffff:127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.97.2 Chrome/128.0.6613.186 Electron/32.2.7 Safari/537.36', 0, '{\"cc\": \"XX\", \"ip\": \"::ffff:127.0.0.1\", \"asn\": \"Unknown\"}', 0.175, '2025-03-21 21:31:55', 'ALLOW');
INSERT INTO `risk_logs` VALUES (27, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0, '2025-03-21 21:41:18', 'ALLOW');
INSERT INTO `risk_logs` VALUES (28, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0, '2025-03-21 21:46:22', 'ALLOW');
INSERT INTO `risk_logs` VALUES (29, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0, '2025-03-21 21:48:30', 'ALLOW');
INSERT INTO `risk_logs` VALUES (30, '1740483425007', '::1', 'Mozilla/5.0 (iPad; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0, '2025-03-21 21:48:54', 'ALLOW');
INSERT INTO `risk_logs` VALUES (31, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0, '2025-03-21 21:49:12', 'ALLOW');
INSERT INTO `risk_logs` VALUES (32, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0, '2025-03-21 21:49:23', 'ALLOW');
INSERT INTO `risk_logs` VALUES (33, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0, '2025-03-21 21:56:18', 'ALLOW');
INSERT INTO `risk_logs` VALUES (34, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0, '2025-03-21 21:57:50', 'ALLOW');
INSERT INTO `risk_logs` VALUES (35, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0, '2025-03-21 22:00:26', 'ALLOW');
INSERT INTO `risk_logs` VALUES (36, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0, '2025-03-21 22:03:55', 'ALLOW');
INSERT INTO `risk_logs` VALUES (37, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0, '2025-03-21 22:07:26', 'ALLOW');
INSERT INTO `risk_logs` VALUES (38, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0, '2025-03-21 22:11:51', 'ALLOW');
INSERT INTO `risk_logs` VALUES (39, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0, '2025-03-21 22:17:05', 'ALLOW');
INSERT INTO `risk_logs` VALUES (40, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0, '2025-03-21 22:32:52', 'ALLOW');
INSERT INTO `risk_logs` VALUES (41, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0, '2025-03-21 22:51:49', 'ALLOW');
INSERT INTO `risk_logs` VALUES (42, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0, '2025-03-22 10:37:16', 'ALLOW');
INSERT INTO `risk_logs` VALUES (43, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0, '2025-03-22 10:46:16', 'ALLOW');
INSERT INTO `risk_logs` VALUES (44, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0, '2025-03-22 10:51:38', 'ALLOW');
INSERT INTO `risk_logs` VALUES (45, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0, '2025-03-22 10:55:59', 'ALLOW');
INSERT INTO `risk_logs` VALUES (46, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0, '2025-03-22 10:56:51', 'ALLOW');
INSERT INTO `risk_logs` VALUES (47, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0, '2025-03-22 11:00:33', 'ALLOW');
INSERT INTO `risk_logs` VALUES (48, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0, '2025-03-22 11:08:45', 'ALLOW');
INSERT INTO `risk_logs` VALUES (49, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0, '2025-03-22 11:14:30', 'ALLOW');
INSERT INTO `risk_logs` VALUES (50, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0, '2025-03-22 11:15:47', 'ALLOW');
INSERT INTO `risk_logs` VALUES (51, '1740483425007', '::1', 'Mozilla/5.0 (Linux; U; Android 8.1.0; en-US; Nexus 6P Build/OPM7.181205.001) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/134.0.0.0 UCBrowser/12.11.1.1197 Mobile Safari/537.36', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0, '2025-03-22 11:23:44', 'ALLOW');
INSERT INTO `risk_logs` VALUES (52, '1740483425007', '::1', 'Mozilla/5.0 (Linux; U; Android 8.1.0; en-US; Nexus 6P Build/OPM7.181205.001) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/134.0.0.0 UCBrowser/12.11.1.1197 Mobile Safari/537.36', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0, '2025-03-22 11:35:39', 'ALLOW');
INSERT INTO `risk_logs` VALUES (53, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0, '2025-03-22 14:51:23', 'ALLOW');
INSERT INTO `risk_logs` VALUES (54, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0.0001, '2025-03-23 18:27:42', 'ALLOW');
INSERT INTO `risk_logs` VALUES (55, '1740483425007', '::1', 'Mozilla/5.0 (BB10; Touch) AppleWebKit/537.1+ (KHTML, like Gecko) Version/10.0.0.1337 Mobile Safari/537.1+', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0.0001, '2025-03-23 18:30:31', 'ALLOW');
INSERT INTO `risk_logs` VALUES (56, '1740483425007', '::1', 'Mozilla/5.0 (BB10; Touch) AppleWebKit/537.1+ (KHTML, like Gecko) Version/10.0.0.1337 Mobile Safari/537.1+', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0.0001, '2025-03-23 18:37:52', 'ALLOW');
INSERT INTO `risk_logs` VALUES (57, '1740483425007', '::1', 'Mozilla/5.0 (BB10; Touch) AppleWebKit/537.1+ (KHTML, like Gecko) Version/10.0.0.1337 Mobile Safari/537.1+', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0.0001, '2025-03-23 18:42:05', 'ALLOW');
INSERT INTO `risk_logs` VALUES (58, '1740483425007', '::1', 'Mozilla/5.0 (BB10; Touch) AppleWebKit/537.1+ (KHTML, like Gecko) Version/10.0.0.1337 Mobile Safari/537.1+', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0.0001, '2025-03-23 18:45:19', 'ALLOW');
INSERT INTO `risk_logs` VALUES (59, '1740483425007', '::1', 'Mozilla/5.0 (BB10; Touch) AppleWebKit/537.1+ (KHTML, like Gecko) Version/10.0.0.1337 Mobile Safari/537.1+', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0.0001, '2025-03-23 18:47:54', 'ALLOW');
INSERT INTO `risk_logs` VALUES (60, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0.0001, '2025-03-23 18:48:25', 'ALLOW');
INSERT INTO `risk_logs` VALUES (61, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0.0001, '2025-03-23 18:54:50', 'ALLOW');
INSERT INTO `risk_logs` VALUES (62, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0.0001, '2025-03-23 18:59:42', 'ALLOW');
INSERT INTO `risk_logs` VALUES (63, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0.0001, '2025-03-23 19:03:31', 'ALLOW');
INSERT INTO `risk_logs` VALUES (64, '1742727893857', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0.0025, '2025-03-23 19:05:01', 'ALLOW');
INSERT INTO `risk_logs` VALUES (65, '1742727893857', '::1', 'Mozilla/5.0 (BB10; Touch) AppleWebKit/537.1+ (KHTML, like Gecko) Version/10.0.0.1337 Mobile Safari/537.1+', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0.0015, '2025-03-23 19:05:32', 'ALLOW');
INSERT INTO `risk_logs` VALUES (66, '1742727893857', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0.0008, '2025-03-23 19:05:45', 'ALLOW');
INSERT INTO `risk_logs` VALUES (67, '1742727893857', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0.0005, '2025-03-23 19:05:49', 'ALLOW');
INSERT INTO `risk_logs` VALUES (68, '1742727893857', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0.0005, '2025-03-23 19:05:51', 'ALLOW');
INSERT INTO `risk_logs` VALUES (69, '1742727893857', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0.0003, '2025-03-23 19:05:53', 'ALLOW');
INSERT INTO `risk_logs` VALUES (70, '1742727893857', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0.0003, '2025-03-23 19:05:54', 'ALLOW');
INSERT INTO `risk_logs` VALUES (71, '1742727893857', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0.0002, '2025-03-23 19:05:56', 'ALLOW');
INSERT INTO `risk_logs` VALUES (72, '1742727893857', '::1', 'Mozilla/5.0 (Linux; U; Android 4.0.2; en-us; Galaxy Nexus Build/ICL53F) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0.0002, '2025-03-23 19:06:57', 'ALLOW');
INSERT INTO `risk_logs` VALUES (73, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0.0001, '2025-03-23 21:08:05', 'ALLOW');
INSERT INTO `risk_logs` VALUES (74, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0.0001, '2025-03-23 21:13:16', 'ALLOW');
INSERT INTO `risk_logs` VALUES (75, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0.0001, '2025-03-23 21:18:56', 'ALLOW');
INSERT INTO `risk_logs` VALUES (76, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0', 0, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0.0001, '2025-03-23 21:28:32', 'ALLOW');
INSERT INTO `risk_logs` VALUES (77, '1743344781652', '::ffff:127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.97.2 Chrome/128.0.6613.186 Electron/32.2.7 Safari/537.36', 139, '{\"cc\": \"XX\", \"ip\": \"::ffff:127.0.0.1\", \"asn\": \"Unknown\"}', 0.005, '2025-03-30 22:26:57', 'ALLOW');
INSERT INTO `risk_logs` VALUES (78, '1743344781652', '::ffff:127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Trae/1.97.2 Chrome/128.0.6613.186 Electron/32.2.7 Safari/537.36', 298, '{\"cc\": \"XX\", \"ip\": \"::ffff:127.0.0.1\", \"asn\": \"Unknown\"}', 0.0037, '2025-03-30 22:31:04', 'ALLOW');
INSERT INTO `risk_logs` VALUES (79, '1740483425007', '::1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0', 207, '{\"cc\": \"LOCAL\", \"ip\": \"::1\", \"asn\": \"Local\"}', 0.0001, '2025-04-20 17:07:22', 'ALLOW');

-- ----------------------------
-- Table structure for user_activity_summary
-- ----------------------------
DROP TABLE IF EXISTS `user_activity_summary`;
CREATE TABLE `user_activity_summary`  (
  `user_id` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `total_logins` int NOT NULL DEFAULT 0,
  `unique_ips` int NOT NULL DEFAULT 0,
  `unique_browsers` int NOT NULL DEFAULT 0,
  `unique_devices` int NOT NULL DEFAULT 0,
  `unique_locations` int NOT NULL DEFAULT 0,
  `risk_level` tinyint NULL DEFAULT 0,
  `last_login` timestamp NULL DEFAULT NULL,
  `last_updated` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`user_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of user_activity_summary
-- ----------------------------
INSERT INTO `user_activity_summary` VALUES ('1740483425007', 64, 2, 2, 2, 2, 2, '2025-04-20 17:07:22', '2025-04-21 15:14:45');
INSERT INTO `user_activity_summary` VALUES ('1742727893857', 9, 1, 1, 2, 1, 0, '2025-03-23 19:06:57', '2025-04-21 15:04:24');
INSERT INTO `user_activity_summary` VALUES ('1743344781652', 2, 1, 1, 1, 1, 0, '2025-03-30 22:31:04', '2025-04-21 15:04:24');

SET FOREIGN_KEY_CHECKS = 1;
