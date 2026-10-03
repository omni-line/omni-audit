package main

import "sort"

// npmSeed is used when the live rank dump is unavailable.
func npmSeed() []string {
	base := []string{
		"lodash", "react", "react-dom", "express", "axios", "typescript", "webpack",
		"eslint", "prettier", "jest", "mocha", "chai", "vue", "angular", "next",
		"rxjs", "zone.js", "jquery", "underscore", "moment", "dayjs", "uuid",
		"chalk", "debug", "commander", "yargs", "minimist", "glob", "rimraf",
		"mkdirp", "fs-extra", "cross-env", "dotenv", "nodemon", "ts-node",
		"babel-core", "@babel/core", "@babel/preset-env", "@types/node",
		"@types/react", "@types/jest", "classnames", "prop-types", "redux",
		"react-redux", "vuex", "pinia", "svelte", "solid-js", "preact",
		"webpack-dev-server", "css-loader", "style-loader", "sass", "less",
		"postcss", "autoprefixer", "tailwindcss", "bootstrap", "antd",
		"@mui/material", "@emotion/react", "@emotion/styled", "styled-components",
		"graphql", "apollo-client", "@apollo/client", "socket.io", "ws",
		"jsonwebtoken", "bcrypt", "bcryptjs", "passport", "helmet", "cors",
		"body-parser", "cookie-parser", "morgan", "winston", "pino",
		"ajv", "joi", "yup", "zod", "immer", "reselect", "history",
		"react-router", "react-router-dom", "vue-router",
		"node-fetch", "got", "superagent", "form-data", "multer",
		"sharp", "canvas", "pdfkit", "puppeteer", "playwright", "cypress",
		"vitest", "ava", "tap", "nyc", "istanbul",
		"husky", "lint-staged", "commitlint", "semantic-release",
		"npm", "yarn", "pnpm", "lerna", "nx", "turbo", "vite", "esbuild",
		"rollup", "parcel", "browserify", "gulp", "grunt",
		"left-pad", "is-array", "is-plain-object", "kind-of", "type-fest",
		"tslib", "core-js", "regenerator-runtime", "whatwg-fetch",
		"eventemitter3", "mitt", "nanoid", "shortid", "slugify",
		"semver", "semver-compare", "compare-versions",
		"ms", "bytes", "humanize-ms", "pretty-ms",
		"cli-table3", "ora", "ink", "prompts", "inquirer",
		"electron", "three", "d3", "chart.js", "echarts", "leaflet",
		"immutable", "seamless-immutable", "mobx", "mobx-react",
		"recoil", "jotai", "zustand", "valtio",
		"formik", "react-hook-form", "final-form",
		"i18next", "react-i18next", "intl-messageformat",
		"date-fns", "luxon", "mathjs", "ramda", "lodash-es",
		"async", "bluebird", "koa", "fastify", "hapi", "restify",
		"@nestjs/core", "typeorm", "sequelize", "mongoose", "prisma", "@prisma/client",
		"knex", "pg", "mysql", "mysql2", "mongodb", "redis", "ioredis",
		"amqplib", "kafkajs", "bull", "aws-sdk", "@aws-sdk/client-s3",
		"firebase", "firebase-admin", "stripe", "twilio", "@sendgrid/mail",
		"openid-client", "passport-local", "passport-jwt",
		"markdown-it", "marked", "cheerio", "jsdom",
		"yaml", "js-yaml", "toml", "ini", "dotenv-expand",
		"loglevel", "bunyan", "log4js", "sinon", "nock", "msw", "supertest",
		"@testing-library/react", "@testing-library/jest-dom", "@storybook/react",
		"webpack-cli", "webpack-merge", "html-webpack-plugin",
		"babel-loader", "ts-loader", "vue-loader",
		"eslint-plugin-react", "eslint-plugin-import",
		"@typescript-eslint/parser", "@typescript-eslint/eslint-plugin",
		"stylelint", "cross-spawn", "execa", "shelljs",
		"graceful-fs", "chokidar", "source-map", "source-map-support",
		"acorn", "espree", "esprima", "recast", "@babel/parser", "@babel/traverse",
		"resolve", "find-up", "locate-path", "read-pkg", "write-pkg",
		"validate-npm-package-name", "npm-package-arg", "pacote",
		"tar", "archiver", "mime", "mime-types", "content-type",
		"accepts", "type-is", "http-errors", "statuses",
		"qs", "query-string", "url-parse", "follow-redirects",
		"readable-stream", "safe-buffer", "inherits",
		"object-assign", "deepmerge", "extend", "micromatch", "braces",
		"isobject", "is-buffer", "kind-of",
	}
	seen := map[string]struct{}{}
	var out []string
	for _, n := range base {
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
