module.exports = {
    env: {
        es2021: true,
        node: true,
    },
    parser: '@typescript-eslint/parser',
    extends: [
        'plugin:@typescript-eslint/recommended',
        'plugin:prettier/recommended',
    ],
    parserOptions: {
        ecmaVersion: 2018,
        sourceType: 'module',
    },
    rules: {},
};
