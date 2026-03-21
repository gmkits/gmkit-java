package cn.gmkit.sm2;

import cn.gmkit.core.Bytes;

/**
 * @author mumu
 * @description SM2密钥交换选项配置类
 * @since 1.0.0
 */
public final class SM2KeyExchangeOptions {

    private final boolean initiator;
    private final int keyBits;
    private final String selfId;
    private final String peerId;
    private final byte[] confirmationTag;

    private SM2KeyExchangeOptions(Builder builder) {
        this.initiator = builder.initiator;
        this.keyBits = builder.keyBits;
        this.selfId = builder.selfId;
        this.peerId = builder.peerId;
        this.confirmationTag = Bytes.clone(builder.confirmationTag);
    }

    /**
     * 创建构建器
     *
     * @return 构建器实例
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * 是否为密钥交换发起方
     *
     * @return 如果是发起方返回true，否则返回false
     */
    public boolean initiator() {
        return initiator;
    }

    /**
     * 获取密钥位数
     *
     * @return 密钥位数
     */
    public int keyBits() {
        return keyBits;
    }

    /**
     * 获取己方ID
     *
     * @return 己方ID
     */
    public String selfId() {
        return selfId;
    }

    /**
     * 获取对方ID
     *
     * @return 对方ID
     */
    public String peerId() {
        return peerId;
    }

    /**
     * 获取确认标签
     *
     * @return 确认标签的字节数组克隆
     */
    public byte[] confirmationTag() {
        return Bytes.clone(confirmationTag);
    }

    /**
     * SM2密钥交换选项构建器
     */
    public static final class Builder {
        private boolean initiator;
        private int keyBits = 128;
        private String selfId = SM2.DEFAULT_USER_ID;
        private String peerId = SM2.DEFAULT_USER_ID;
        private byte[] confirmationTag;

        private Builder() {
        }

        /**
         * 设置是否为发起方
         *
         * @param initiator 是否为发起方
         * @return 构建器实例
         */
        public Builder initiator(boolean initiator) {
            this.initiator = initiator;
            return this;
        }

        /**
         * 设置密钥位数
         *
         * @param keyBits 密钥位数
         * @return 构建器实例
         */
        public Builder keyBits(int keyBits) {
            this.keyBits = keyBits;
            return this;
        }

        /**
         * 设置己方ID
         *
         * @param selfId 己方ID
         * @return 构建器实例
         */
        public Builder selfId(String selfId) {
            this.selfId = cn.gmkit.core.Checks.defaultIfNull(selfId, SM2.DEFAULT_USER_ID);
            return this;
        }

        /**
         * 设置对方ID
         *
         * @param peerId 对方ID
         * @return 构建器实例
         */
        public Builder peerId(String peerId) {
            this.peerId = cn.gmkit.core.Checks.defaultIfNull(peerId, SM2.DEFAULT_USER_ID);
            return this;
        }

        /**
         * 设置确认标签
         *
         * @param confirmationTag 确认标签字节数组
         * @return 构建器实例
         */
        public Builder confirmationTag(byte[] confirmationTag) {
            this.confirmationTag = Bytes.clone(confirmationTag);
            return this;
        }

        /**
         * 构建密钥交换选项对象
         *
         * @return 密钥交换选项实例
         */
        public SM2KeyExchangeOptions build() {
            return new SM2KeyExchangeOptions(this);
        }
    }
}

