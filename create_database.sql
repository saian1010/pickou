create database pickou;

-- users
CREATE TABLE users (
    user_id BIGINT NOT NULL AUTO_INCREMENT,
    username VARCHAR(20) NOT NULL Default "",
    password_hash CHAR(60) BINARY NOT NULL,
    email VARCHAR(320) NOT NULL Default "",
    phone VARCHAR(50) NOT NULL Default "",
    dob_year int(10) NOT NULL Default 0,
    dob_month int(10) NOT NULL Default 0,
    first_name VARCHAR(50) NOT NULL Default 'N/A',
    last_name VARCHAR(50) NOT NULL Default 'N/A',
    nick_name VARCHAR(50) NOT NULL Default 'N/A',
    gender int(2) NOT NULL Default 0 comment '性别，0未知，1男，2女，3无性别',
    nationality VARCHAR(20) NOT NULL Default "" comment '国籍',
    profile_image VARCHAR(255) NOT NULL Default '',
    role ENUM('visitor', 'helper', 'admin') NOT NULL Default 'visitor' comment '默认visitor',
    authenticate int(2) NOT NULL Default 0 comment '0未认证，1已认证',
    status ENUM('active', 'inactive') NOT NULL Default 'active',
    created_at TIMESTAMP NOT NULL Default CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id)
);

-- issues
CREATE TABLE issues (
    issue_id BIGINT NOT NULL AUTO_INCREMENT,
    user_id BIGINT NOT NULL,
    vote_id BIGINT NOT NULL,
    summary VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    status ENUM('new', 'open', 'stalled', 'resolved') NOT NULL,
    PRIMARY KEY (issue_id)
);

CREATE TABLE votes(
    vote_id BIGINT NOT NULL AUTO_INCREMENT,
    title VARCHAR(50) NOT NULL Default '',
    vote_type int(2) NOT NULL Default 1 comment '1单选，2多选',
    vote_option_id BIGINT NOT NULL,
    PRIMARY KEY (vote_id)
);

CREATE TABLE vote_options(
    vote_option_id BIGINT NOT NULL AUTO_INCREMENT,
    title VARCHAR(50) NOT NULL Default '',
    PRIMARY KEY (vote_option_id)
);

-- 用户投票记录表
CREATE TABLE user_votes(
    user_vote_id BIGINT NOT NULL AUTO_INCREMENT,
    user_id BIGINT NOT NULL comment '用户id',
    vote_id BIGINT NOT NULL comment '投票id',
    vote_option_id BIGINT NOT NULL comment '投票选项id',
    PRIMARY KEY (user_vote_id)
);

-- comments
CREATE TABLE comments (
    comment_id INT NOT NULL AUTO_INCREMENT,
    issue_id INT NOT NULL,
    user_id INT NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    PRIMARY KEY (comment_id)
);