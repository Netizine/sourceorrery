import { defineCollection } from 'astro:content';
import { docsLoader } from '@astrojs/starlight/loaders';
import { docsSchema } from '@astrojs/starlight/schema';
import { z } from 'astro/zod';
import { withDocMetadata } from './lib/docs-loader.mjs';

export const collections = {
	docs: defineCollection({
		loader: withDocMetadata(docsLoader()),
		schema: docsSchema({
			extend: z.object({
				// Generated pages name their original repository source here.
				sourceFile: z.string().optional(),
				readingTimeMinutes: z.number().int().positive().optional(),
			}),
		}),
	}),
};
